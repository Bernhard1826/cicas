#!/usr/bin/env python3
"""Synonymy judge — extracted from exp_multi_tool_coverage_v3.py.

Pure-function module. Input is plain text (or text+metadata dicts); the module
makes no assumption about whether the input is a lint rule, a backend rule,
generated code, or anything else. It exposes:

  * embed_texts(texts)            -- batched bge-m3 embeddings
  * cos(a, b)                     -- cosine similarity
  * topk_by_embedding(...)        -- top-K retrieval
  * judge_synonymy(a, candidates) -- LLM full/partial/none verdict

Design contract (kept identical to v3 so behavior matches round5):
  - Embedding model: BAAI/bge-m3 via SiliconFlow
  - LLM:             gpt-5.4, temperature=0
  - Prompt:          v3 paraphrase-strict template (lint↔std interchangeable)
  - Section/citation pre-filter: NONE (deprecated by user — section numbers
                     have drifted, embedding-only recall as instructed)

The prompt is symmetric: the LHS is called "(A)" and the RHS is "(B)
candidates", so callers can swap directions (lint→backend or backend→lint or
generated-code→rule) without rewriting the prompt.
"""
from __future__ import annotations
import json
import os
import re
import time
from typing import Any, Callable, Iterable

import httpx

# ------------------------------------------------------------------ Constants

API_KEY = "sk-obybcwgemcbpscnhhwblfwysawpepglmsfmequdefooqipvd"
API_BASE = "https://api.siliconflow.cn/v1"

# OpenAI-compatible proxy (quan2go) for GPT-5.x -- streaming only
OPENAI_KEY = "061C540A-D19D-47EA-93DB-96A05F2B3F4E"
OPENAI_BASE = "https://capi.quan2go.com/v1"

# Anthropic-native proxy for Claude (set via env). Model IDs starting with
# "claude-" are routed to /v1/messages here instead of SiliconFlow.
ANTHROPIC_KEY  = os.environ.get("ANTHROPIC_API_KEY", "")
ANTHROPIC_BASE = os.environ.get("ANTHROPIC_BASE_URL", "https://api.anthropic.com")

LLM_MODEL = os.environ.get("LLM_MODEL", "gpt-5.4")
EMB_MODEL = "BAAI/bge-m3"

# ---- Unified experiment LLM endpoint (ai.ailink1.com, OpenAI-compatible) -----
# Every experiment LLM task (IR extraction, DSL-tree generation, synonym check,
# binary judge, ...) routes to a single model here.  Overridable via env.
AILINK_KEY    = os.environ.get("AILINK_API_KEY",
                               "sk-94293042a13e21774be92ac6d1153b807f3ea2b15083e70a814fbb49a05b22aa")
AILINK_BASE   = os.environ.get("AILINK_BASE_URL", "https://ai.ailink1.com/v1")
AILINK_MODEL  = os.environ.get("AILINK_MODEL", "gpt-5.4")
# This endpoint REQUIRES a system message (else 400 "Instructions are required").
AILINK_SYSTEM = ("You are a precise assistant for PKI / X.509 certificate rule "
                 "formalization. Follow the user's instructions exactly and output "
                 "only what is requested.")

# ------------------------------------------------------------------ LLM call

def _call_ailink(prompt: str, max_tokens: int, temperature: float) -> str:
    """Call the unified ai.ailink1.com OpenAI-compatible endpoint (gpt-5.4).
    A system message is mandatory for this endpoint."""
    base_payload = {
        "model": AILINK_MODEL,
        "messages": [{"role": "system", "content": AILINK_SYSTEM},
                     {"role": "user", "content": prompt}],
        "temperature": temperature,
    }
    use_token_limit = True
    for attempt in range(6):
        payload = dict(base_payload)
        if use_token_limit:
            payload["max_tokens"] = max_tokens
        try:
            with httpx.Client(trust_env=False, timeout=400.0) as c:
                r = c.post(f"{AILINK_BASE}/chat/completions",
                           headers={"Authorization": f"Bearer {AILINK_KEY}",
                                    "Content-Type": "application/json"},
                           json=payload)
            if r.status_code == 200:
                try:
                    return r.json()["choices"][0]["message"]["content"]
                except Exception:
                    # 200 but body isn't the expected JSON (e.g. an SSE error
                    # frame leaked in) -> transient, retry.
                    if attempt < 5:
                        time.sleep(8 + attempt * 6)
                        continue
                    return f"__ERROR__ 200-unparseable: {r.text[:200]}"
            body = r.text
            if (r.status_code == 400
                    and use_token_limit
                    and "Unsupported parameter" in body
                    and any(name in body for name in (
                        "max_tokens", "max_output_tokens", "max_completion_tokens",
                    ))):
                use_token_limit = False
                continue
            # ai.ailink1.com intermittently fails its upstream and returns a
            # transient error (often HTTP 400 carrying an SSE 'upstream_error');
            # treat that as retryable, not a real bad request.
            transient = (r.status_code in (429, 500, 502, 503, 504)
                         or "upstream_error" in body
                         or "Upstream request failed" in body)
            if transient and attempt < 5:
                time.sleep(8 + attempt * 6)
                continue
            return f"__ERROR__ {r.status_code}: {body[:200]}"
        except httpx.ReadTimeout:
            time.sleep(20 + attempt * 10)
        except Exception:
            time.sleep(10 + attempt * 5)
    return "__ERROR__ max_retries"


def _call_openai_stream(model: str, prompt: str, max_tokens: int, temperature: float) -> str:
    """Call the quan2go OpenAI-compatible proxy; it always streams."""
    payload = {
        "model": model,
        "messages": [{"role": "user", "content": prompt}],
        "max_tokens": max_tokens,
        "temperature": temperature,
        "stream": True,
    }
    for attempt in range(5):
        try:
            with httpx.Client(trust_env=False, timeout=400.0) as c:
                with c.stream("POST", f"{OPENAI_BASE}/chat/completions",
                              headers={"Authorization": f"Bearer {OPENAI_KEY}",
                                       "Content-Type": "application/json"},
                              json=payload) as r:
                    if r.status_code != 200:
                        body = r.read().decode(errors="replace")[:300]
                        if r.status_code in (429, 500, 502, 503, 504):
                            time.sleep(15 + attempt * 10)
                            continue
                        return f"__ERROR__ {r.status_code}: {body}"
                    chunks: list[str] = []
                    for line in r.iter_lines():
                        if not line or not line.startswith("data: "):
                            continue
                        data = line[6:]
                        if data == "[DONE]":
                            break
                        try:
                            j = json.loads(data)
                            d = j.get("choices", [{}])[0].get("delta", {})
                            if d.get("content"):
                                chunks.append(d["content"])
                        except Exception:
                            pass
                    return "".join(chunks)
        except httpx.ReadTimeout:
            time.sleep(20 + attempt * 10)
        except Exception:
            time.sleep(10 + attempt * 5)
    return "__ERROR__ max_retries"


def _call_anthropic(model: str, prompt: str, max_tokens: int, temperature: float) -> str:
    """Call an Anthropic-native /v1/messages endpoint (native or proxy).
    Reads ANTHROPIC_API_KEY / ANTHROPIC_BASE_URL from env at import time."""
    if not ANTHROPIC_KEY:
        return "__ERROR__ ANTHROPIC_API_KEY not set"
    payload = {
        "model": model,
        "max_tokens": max_tokens,
        "temperature": temperature,
        "messages": [{"role": "user", "content": prompt}],
    }
    headers = {
        "x-api-key": ANTHROPIC_KEY,
        "anthropic-version": "2023-06-01",
        "content-type": "application/json",
    }
    for attempt in range(5):
        try:
            with httpx.Client(trust_env=False, timeout=400.0) as c:
                r = c.post(f"{ANTHROPIC_BASE}/v1/messages",
                           headers=headers, json=payload)
            if r.status_code == 200:
                j = r.json()
                # Anthropic returns content as list of content blocks; concatenate text blocks.
                blocks = j.get("content", [])
                txt = "".join(b.get("text", "") for b in blocks if b.get("type") == "text")
                return txt
            if r.status_code in (429, 500, 502, 503, 504, 529):
                time.sleep(15 + attempt * 10)
                continue
            return f"__ERROR__ {r.status_code}: {r.text[:300]}"
        except httpx.ReadTimeout:
            time.sleep(20 + attempt * 10)
        except Exception as e:
            time.sleep(10 + attempt * 5)
    return "__ERROR__ max_retries"


def call_llm(prompt: str, max_tokens: int = 3500, temperature: float = 0.0,
             model: str | None = None) -> str:
    """Call the unified experiment LLM (ai.ailink1.com / gpt-5.4) with retries;
    return raw assistant content or an __ERROR__ string.

    All experiment LLM tasks — IR extraction, DSL-tree generation, synonym check,
    binary judge — route to one model now, regardless of the requested `model`.
    """
    return _call_ailink(prompt, max_tokens, temperature)


def parse_json_block(raw: str) -> dict | None:
    """Extract a JSON object from LLM output. Tolerant of:
      - markdown fences (```json ... ```)
      - prose before/after the object
      - the LLM emitting the same object twice (once raw, once fenced)
    Strategy: strip optional outer fences, then scan forward from each '{'
    to find the first complete JSON object (balanced braces).  Uses an
    explicit depth counter, NOT Python recursion, so arbitrarily-nested
    LLM output cannot blow the stack.
    """
    if not isinstance(raw, str):
        return None
    s = raw.strip()
    # Strip outer ``` fences if they wrap the whole reply
    for fence in ("```json", "```"):
        if s.startswith(fence):
            s = s[len(fence):].strip()
        if s.endswith(fence):
            s = s[:-len(fence)].strip()
    # Scan forward; accept the first '{' that balances
    n = len(s)
    i = 0
    while i < n:
        if s[i] != '{':
            i += 1
            continue
        # Try to parse from position i using depth counter
        depth = 0
        j = i
        while j < n:
            c = s[j]
            if c == '{':
                depth += 1
            elif c == '}':
                depth -= 1
                if depth == 0:
                    # possible complete object
                    blob = s[i:j+1]
                    try:
                        obj = json.loads(blob)
                        if isinstance(obj, dict):
                            return obj
                    except json.JSONDecodeError:
                        pass
                    break
            j += 1
        i += 1
    return None


# ------------------------------------------------------------------ Embedding

def embed_texts(texts: list[str], batch: int = 8) -> list[list[float]]:
    """Embed a list of strings; returns list of vectors in input order."""
    out: list[list[float]] = []
    for i in range(0, len(texts), batch):
        chunk = texts[i:i + batch]
        for attempt in range(5):
            try:
                with httpx.Client(trust_env=False, timeout=180.0) as c:
                    r = c.post(
                        f"{API_BASE}/embeddings",
                        headers={"Authorization": f"Bearer {API_KEY}",
                                 "Content-Type": "application/json"},
                        json={"model": EMB_MODEL, "input": chunk},
                    )
                    r.raise_for_status()
                    out.extend([d["embedding"] for d in r.json()["data"]])
                break
            except Exception:
                if attempt == 4:
                    raise
                time.sleep(2 ** attempt)
    return out


def cos(a: list[float], b: list[float]) -> float:
    s = sum(x * y for x, y in zip(a, b))
    na = sum(x * x for x in a) ** 0.5
    nb = sum(y * y for y in b) ** 0.5
    return s / (na * nb + 1e-9)


def topk_by_embedding(
    query_emb: list[float],
    pool: list[dict],
    pool_embs: dict[str, list[float]],
    key_fn: Callable[[dict], str],
    topk: int = 30,
) -> list[dict]:
    """Return the top-K items in `pool` whose embedding (looked up via
    key_fn(item) in pool_embs) is most similar to `query_emb`.

    Items missing from pool_embs are silently skipped — caller is responsible
    for ensuring the cache is populated."""
    scored = []
    for item in pool:
        v = pool_embs.get(key_fn(item))
        if v is None:
            continue
        scored.append((cos(query_emb, v), item))
    scored.sort(key=lambda x: -x[0])
    return [item for _, item in scored[:topk]]


# ------------------------------------------------------------------ Prompt

# Prompt is the v3 paraphrase-strict template.  It is direction-agnostic: (A)
# and (B) can be lint→standard, standard→lint, or generated-code→standard;
# the synonymy criterion is the same.
PROMPT = """You are judging semantic EQUIVALENCE (synonymy) between two
normative requirements -- one labeled (A), one labeled (B).

This is NOT a "related topic" test. Two requirements are equivalent only if
you can paraphrase one as the other without changing its meaning. "Same
extension but different bit", "same section but different field", "related
area" -- all of these are NOT equivalent.

=== (A) {a_label} ===
{a_text}

=== (B) Candidate {b_label}s ===
{menu}

=== DECIDE FOR EACH CANDIDATE ===

  "full"    -> (A) and the candidate say the SAME THING. If both sentences
               were handed to a PKI expert, they would call them paraphrases
               of each other. Same field, same obligation direction, same
               constraint/value.

  "partial" -> The candidate enforces a STRICT SUBSET of (A). The candidate
               enforces one of multiple conditions named in (A), OR a
               stricter/weaker variant of the same constraint. Still same
               field and direction, still about the same thing -- just
               narrower.

  "none"    -> everything else, INCLUDING:
               * same section / extension but different field / bit / aspect
               * related topic but different rule
               * same field but different direction (MUST vs MUST NOT, etc.)
               * same field but different constraint (length vs value, etc.)
               * merely "in the neighborhood"

=== EXAMPLES ===

  (A) : "Serial number MUST be greater than zero."
  (B) : "The serial number MUST be a positive integer."
  -> full (synonymous).

  (A) : "Serial number MUST NOT be longer than 20 octets."
  (B) : "The serial number MUST be a positive integer."
  -> none (different constraint: length vs positivity, NOT synonymous).

  (A) : "The extension MUST be present."
  (B) : "The extension MUST be marked critical."
  -> none (presence vs criticality, NOT synonymous).

  (A) : "Key usage MUST assert digitalSignature."
  (B) : "Key usage MUST assert both digitalSignature and keyEncipherment."
  -> partial (a strict subset, same field and direction).

  (A) : "The subject commonName length MUST NOT exceed 32 characters."
  (B) : "The subject commonName length MUST NOT exceed 64 characters."
  -> partial (stricter variant of same constraint).

  (A) : "The authorityInfoAccess extension MUST contain an HTTP URI."
  (B) : "CRL distribution points MUST contain at least one HTTP URI."
  -> none (different fields, AIA vs CRL; do NOT mark based on topic
     similarity).

=== OUTPUT ===

Return ONLY a JSON object. Omit candidates whose verdict is "none":

{{
  "picks": [
    {{"index": <1..N>, "verdict": "full" | "partial",
      "why": "<one sentence: why these two are synonymous>"}},
    ...
  ]
}}
If nothing is synonymous, return `{{"picks": []}}`. Do NOT emit any prose
outside the JSON.
"""


def _default_render(c: dict) -> str:
    """Default per-candidate rendering: show a couple of common fields."""
    out = []
    for k in ("description", "code_summary", "summary", "text", "code"):
        v = c.get(k)
        if v:
            out.append(f"    {k}: {str(v)[:600]}")
    if not out:
        # fall back to whatever fields the dict has
        out = [f"    {k}: {str(v)[:300]}" for k, v in c.items() if v]
    return "\n".join(out)


def build_menu(candidates: list[dict],
               render_fn: Callable[[dict], str] = _default_render) -> str:
    lines = []
    for i, c in enumerate(candidates, 1):
        head = f"[{i}]"
        for k in ("rule_id", "id", "tool", "source", "section"):
            if c.get(k) is not None:
                head += f"  {k}={c[k]}"
        lines.append(head + "\n" + render_fn(c))
    return "\n".join(lines)


# ------------------------------------------------------------------ Judge API

def judge_synonymy(
    a_text: str,
    candidates: list[dict],
    a_label: str = "Source rule",
    b_label: str = "rule",
    render_fn: Callable[[dict], str] = _default_render,
) -> dict:
    """Run a single LLM call comparing (A) `a_text` against the menu of B
    candidates, and return:

        {
          "verdict": "full" | "partial" | "none" | "api_error",
          "picks":   [{"index": int, "verdict": "full|partial",
                       "why": str, "candidate": dict}, ...],
          "reason":  "ok" | "no_candidates" | "llm_rejected" | "api_error",
          "raw":     <last 200 chars of LLM output, for debugging>,
        }

    `verdict` is the best across all picks (full > partial > none). `picks`
    contains the original candidate dict for each pick so callers can
    propagate metadata downstream.

    `render_fn(candidate) -> str` controls how each candidate is shown to the
    LLM. Default shows description/code_summary/summary/text/code fields.
    """
    if not candidates:
        return {"verdict": "none", "picks": [],
                "reason": "no_candidates", "raw": ""}

    menu = build_menu(candidates, render_fn=render_fn)
    prompt = PROMPT.format(
        a_label=a_label,
        a_text=(a_text or "")[:1500],
        b_label=b_label,
        menu=menu,
    )
    raw = call_llm(prompt)
    if isinstance(raw, str) and raw.startswith("__ERROR__"):
        return {"verdict": "api_error", "picks": [],
                "reason": "api_error", "raw": raw[:200]}

    obj = parse_json_block(raw) or {}
    picks_raw = obj.get("picks") or []
    picks: list[dict] = []
    best = "none"
    for p in picks_raw:
        try:
            idx = int(p.get("index"))
        except (TypeError, ValueError):
            continue
        if not (1 <= idx <= len(candidates)):
            continue
        v = str(p.get("verdict") or "").lower()
        if v not in ("full", "partial"):
            continue
        picks.append({
            "index": idx,
            "verdict": v,
            "why": (p.get("why") or "")[:300],
            "candidate": candidates[idx - 1],
        })
        if v == "full":
            best = "full"
        elif v == "partial" and best != "full":
            best = "partial"

    return {"verdict": best, "picks": picks,
            "reason": "ok" if picks else "llm_rejected",
            "raw": raw[-200:] if isinstance(raw, str) else ""}


# ------------------------------------------------------------------ Self-test

def _self_test() -> None:
    """Quick smoke-test against a known-synonymous pair (no DB needed)."""
    print("Embedding round-trip ...")
    vs = embed_texts([
        "The serial number MUST be a positive integer.",
        "Serial number MUST be greater than zero.",
        "The extension MUST be marked critical.",
    ])
    print(f"  got {len(vs)} vectors, dim={len(vs[0])}")
    print(f"  cos(positive, gt-zero)   = {cos(vs[0], vs[1]):.3f}")
    print(f"  cos(positive, critical)  = {cos(vs[0], vs[2]):.3f}")

# ============================================================================
# binary_judge — judge Expresses/Does_Not_Express (codegen emission gate)
# Uses this module's call_llm / parse_json_block so there is exactly ONE
# LLM call path.
# ============================================================================

JUDGE_PROMPT = """You are evaluating whether a piece of generated code FULLY
expresses the meaning of a normative rule.

CONTEXT: The code below was AUTO-GENERATED from the rule with the explicit
goal of expressing every clause of the rule. There is no separate
"partially-correct" outcome -- if any clause is missing, reversed, narrowed,
widened, or replaced by an unstated precondition, the code does NOT
faithfully express the rule.

GO FIELD-NAME NOTE: The code references zcrypto cert struct field names.
The following Go field names are EQUIVALENT to the RDN attribute names from
the rule text -- treat them as the same thing:
  c.Subject.Province                 = stateOrProvinceName
  c.Subject.OrganizationalUnit       = organizationalUnitName
  c.Subject.Organization             = organizationName
  c.Subject.Locality                 = localityName
  c.Subject.Country                  = countryName
  c.Subject.CommonName               = commonName
  c.Subject.GivenName                = givenName
  c.Subject.Surname                  = surname
  c.Subject.SerialNumber             = serialNumber
  c.Subject.OrganizationIDs          = organizationIdentifier
  c.Subject.JurisdictionLocality     = jurisdictionLocalityName
  c.Subject.JurisdictionProvince     = jurisdictionStateOrProvinceName
  c.Subject.JurisdictionCountry      = jurisdictionCountryName
  c.Subject.PostalCode               = postalCode
  c.Subject.StreetAddress            = streetAddress
  c.Subject.EmailAddress             = emailAddress
  c.Subject.DomainComponent          = domainComponent
  c.DNSNames                         = SAN dNSName entries
  c.EmailAddresses                   = SAN rfc822Name entries
  c.IPAddresses                      = SAN iPAddress entries
  c.URIs                             = SAN uniformResourceIdentifier entries
  (the same applies for c.Issuer.* on issuer DN attributes)
A check on c.Subject.Province IS a check on stateOrProvinceName -- they are
the same field, just different names in two namespaces.

PRESENCE-CHECK EQUIVALENCE: For list-valued Go fields (e.g. c.Subject.Province
is []string, c.DNSNames is []string, c.URIs is []string), the canonical way
to check "the attribute is PRESENT" is `len(field) > 0` (i.e. "non-empty").
Therefore:
  - "len(c.Subject.Province) > 0"  EXPRESSES  "stateOrProvinceName is present"
  - "len(c.DNSNames) > 0"          EXPRESSES  "dNSName is present in SAN"
  - "len(c.Subject.Country) == 0"  EXPRESSES  "countryName is absent"
Do NOT mark these as DOES_NOT_EXPRESS just because the rule used "present"
and the code uses "non-empty" -- in Go, those are the same thing for lists.

OR-ALTERNATIVE COVERAGE: If (A) states a constraint over "X or Y" / "X and Y"
alternatives, then (B) faithfully covers the rule when it applies that same
constraint to both named alternatives. Do NOT reject (B) as overbroad merely
because it covers one alternative and the other alternative named by (A).

EXTENSION-DERIVED FLAT FIELDS: zcrypto pre-parses several extensions into
flat top-level []byte / []string fields on Certificate. A check on the flat
field IS a check on the parsed sub-field of the extension:
  c.AuthorityKeyId         = AKI extension's keyIdentifier sub-field
  c.SubjectKeyId           = SKI extension content
  c.OCSPServer             = AIA entries with accessMethod=id-ad-ocsp
  c.IssuingCertificateURL  = AIA entries with accessMethod=id-ad-caIssuers
  c.CRLDistributionPoints  = CRLDP distributionPoint URI list
  c.PolicyIdentifiers      = CertificatePolicies policyIdentifier list
  c.DNSNames / c.EmailAddresses / c.URIs / c.IPAddresses
                           = SAN dNSName / rfc822Name / URI / iPAddress entries
For CertificatePolicies, zcrypto's c.PolicyIdentifiers contains one parsed
policyIdentifier for each PolicyInformation entry in the extension. Therefore,
counting c.PolicyIdentifiers is a faithful way to count PolicyInformation
entries when the row is about the number of PolicyInformation values, unless
the rule also constrains another PolicyInformation subfield not represented in
that list.

IP ADDRESS FIELD-TYPE DISTINCTION: Do not transfer the SAN iPAddress binary
OCTET STRING encoding rule to DN/subject string attributes. When (A) constrains
a string-valued field such as subject commonName and says that an IPv4 address
value uses an IPv4Address/IPv4 address textual form, a check for four
dotted-decimal decimal-octets in that string field EXPRESSES the text syntax.
Only rules whose field is SAN iPAddress / c.IPAddresses require the X.509
GeneralName iPAddress OCTET STRING length/content interpretation.

DNS NAME PHRASE SCOPE: A phrase such as "the Fully-Qualified Domain Name or
the FQDN portion of the Wildcard Domain Name" names two cases: ordinary FQDNs
and wildcard names after removing the leading "*." label. A predicate covering
both ordinary FQDN commonName/dNSName values and the FQDN portion of wildcard
values is not overbroad merely because it covers the ordinary-FQDN half.

X.509 NAME SCOPE: In X.509 prose, an unqualified `Name`,
`RelativeDistinguishedName`, or `RDNSequence` is the generic Name type unless
the source-owned section/table context scopes the row to a specific certificate
field such as RFC5280 §4.1.2.4 Issuer or RFC5280 §4.1.2.6 Subject. Use that
section/table context when the extracted rule text omits the field name. If the
source text/context says "When encoding a Name" or "Each
Name/RelativeDistinguishedName" without a Subject-only or Issuer-only context,
code that checks both Subject DN and Issuer DN can faithfully EXPRESS the rule.
Do not reject it as overbroad merely because the extracted IR subject was
"subject"; the original text/context controls synonymy.
DIRECTORYSTRING TYPE SCOPE: A rule about "attribute values of type
DirectoryString" applies only to attributes whose ASN.1 value type is
DirectoryString. Code that checks DirectoryString-typed RDN attributes and
skips non-DirectoryString attributes such as countryName, domainComponent,
emailAddress, serialNumber, or dnQualifier does not drop those attributes; they
are outside the DirectoryString type scope or are table-defined exceptions.

DN BYTE EQUALITY: c.RawSubject and c.RawIssuer are DER-encoded distinguished
names. A check "bytes.Equal(c.RawSubject, c.RawIssuer)" directly encodes
"subject DN MUST be byte-for-byte identical to issuer DN" or a self-issued
subject==issuer requirement. It does NOT express a rule that merely requires
the same DirectoryString/attribute encoding style between different issuer and
subject names, such as RFC 5280 "subject field MUST be encoded in the same way
as it is encoded in the issuer field"; that rule permits different DN values.

SEVERITY EQUIVALENCE: lint.Error <=> MUST/MUST NOT/SHALL/PROHIBITED;
lint.Warn <=> SHOULD/SHOULD NOT/RECOMMENDED/NOT RECOMMENDED.
MAY/OPTIONAL rows are filtered by lintability C1 and are not generated as
violation lints.
A code returning lint.Warn for a SHOULD rule IS faithful.
A code returning lint.Warn when a NOT RECOMMENDED/SHOULD NOT condition is
present is also faithful; do NOT reject it as a hard prohibition merely because
the generated pass condition is the recommended/advised state. In zlint,
lint.Warn is the advisory finding level.
For a NOT RECOMMENDED row such as "field X | NOT RECOMMENDED | If present",
a lint.Warn when X is present and Pass when X is absent EXPRESSES the row; the
warning severity is the distinction from a MUST NOT prohibition.
Likewise, a SHOULD NOT source row is advisory. A lint.Warn on the discouraged
state EXPRESSES SHOULD NOT; do not require lint.Error unless (A) says MUST NOT,
SHALL NOT, prohibited, or an equivalent hard ban.

CONDITIONAL CHECKAPPLIES EQUIVALENCE: A source rule of the form "if/when C,
P MUST/SHOULD hold" may be implemented by zlint as CheckApplies(C) plus
Execute(P). Outside C, zlint reports NA rather than Pass; that is faithful for
certificate-violation detection and is not an extra precondition. However,
reject a lint when CheckApplies is the very fact that P is supposed to require
(for example, a rule requiring policy OID X must not have CheckApplies require
that OID X already be present).
	For extension criticality/content rows such as "this extension MUST be marked
	critical" or "extension E MUST be non-critical", CheckApplies(extension present)
	is faithful: criticality/content exists only for a present extension, while a
	missing mandatory extension is a separate presence requirement.
	Example: (A) "If the subject field is an empty SEQUENCE, the subjectAltName
	extension MUST be marked critical"; (B) CheckApplies(subject empty AND
	subjectAltName present) plus Execute(subjectAltName critical) -> EXPRESSES.
	OPTIONAL EXTENSION CONTENT ROWS: If the source-owned surrounding text says an
	extension may be omitted, or may be indicated either by omission or by including
	the extension with a specified subfield value, then a table row constraining
	that subfield is satisfied by omission as well as by the specified value. In
	that case, code whose pass condition is "extension absent OR subfield has the
	required value" can EXPRESS the row. Do not reject it merely because the terse
	table row names only the subfield. If the surrounding text instead requires the
	extension to be present, omission is not a valid substitute.
	CONDITIONAL FALLBACK EQUIVALENCE: A rule of the form "if no X is present,
	include fallback marker/value Y" is logically satisfied by the pass condition
	"X is present OR Y is present". Do not reject this form merely because (B)
	mentions the ordinary X branch; that branch is the case where the source
	antecedent "no X" is false. The fallback Y must still be checked exactly.
	NEGATED EXISTENTIALS: A pass condition written as
	"NOT (contains at least one item whose field/property P is present)" means
	there is no such item; equivalently, every relevant item lacks P. Do not
	misread this as "at least one item lacks P".
	NAMECONSTRAINTS IP EXCLUDE-ALL: In X.509 nameConstraints, an iPAddress
GeneralSubtree is encoded as address bytes plus mask bytes. Excluding all
iPAddress names means covering both IP address families: the IPv4 0.0.0.0/0
all-zero 8-octet marker and the IPv6 ::0/0 all-zero 32-octet marker. For a
rule that allows omission of permittedSubtrees iPAddress only when
excludedSubtrees excludes all iPAddress names, requiring both markers is not
an unjustified narrowing.

FINAL-LINT SCOPE STRICTNESS: When (B) says "The final generated in-tree zlint
certificate lint applies to X", X is the actual zlint CheckApplies scope and
is part of the generated lint's meaning. It must be equivalent to the rule's
scope in (A). A superclass or neighboring profile is NOT equivalent to a
narrower profile named by (A): for example, "Subordinate CA certificates" does
NOT express "Cross-Certified Subordinate CA certificates" or "Technically
Constrained Non-TLS Subordinate CA certificates"; "Subscriber certificates"
does NOT express "Organization Validated Subscriber certificates" unless (A)
really applies to all subscriber certificates. Reject (B) if CheckApplies is
broader, narrower, or missing a profile/time condition stated by (A).

ISSUER-ACTOR VS CERTIFICATE-TYPE SCOPE: In RFC/CABF prose, wording like
"CAs MUST encode/force/use ..." usually names the obligated issuing actor; it
does NOT by itself mean the lint should apply only to certificates whose subject
is a CA. Infer a CA-certificate scope only when (A) says "CA certificate(s)",
"conforming CA certificates", a CA certificate profile/table, or an equivalent
certificate-type condition. For actor-scoped certificate encoding constraints
such as serialNumber format, applying the lint to issued certificates generally
does not add a CA-certificate-only scope.
For RFC certificate-content rules expressed as "CAs MUST force/use ..." and
for CABF issuance prohibitions expressed as "CAs SHALL NOT issue Certificates
containing ...", a certificate lint that checks the prohibited/required
certificate property on the applicable certificate type is faithful; do not
reject solely because (A) names the CA actor and (B) describes certificate
instances.
Example: (A) "Conforming CAs MUST NOT use serialNumber values longer than
20 octets"; (B) "all parsed certificates pass only when SerialNumber length is
at most 20 octets" -> EXPRESSES.
KEYCERTSIGN SCOPE: For rules scoped to certificates whose public keys are used
to validate signatures on certificates, the certificate-observable keyUsage
signal is the keyCertSign bit. A lint scoped to KeyUsage keyCertSign and then
checking the required property expresses that usage condition. If the source
also says "CA certificates", the lint must also include a CA-certificate
condition; keyCertSign alone is not equivalent to "CA certificate".

CROSS-CERTIFICATE RELATIONS: Reject (B) when (A) relates this certificate to
certificates or CRLs that it issues, unless (B) explicitly models that other
artifact. For example, RFC 5280 "the subject key identifier MUST be the value
placed in the authority key identifier extension of certificates issued by the
subject of this certificate" is NOT a same-certificate requirement that this
certificate's SKI equals this certificate's AKI.

	TABLE-FRAGMENT STRICTNESS: Some (A) inputs are extracted rows from a larger
	standards table. If (A) includes "Nearby rows from the same source
	section/table", use those rows to interpret terse cells such as "MUST /",
	"MUST / MAY", or a blank value column. Do not treat one fragment row as a
	complete standalone rule when the nearby rows define alternatives or
	conditional presence. For example, if nearby rows show attribute X is required
	when Y is absent and attribute Y is required when X is absent, then (B) does
	NOT express the table by unconditionally requiring only X or only Y; it drops
	the alternative.
	At the same time, do not require (B) to enforce every sibling row in the same
	table. Nearby rows provide scope and disambiguation, but a sibling row is not
	part of (A)'s required predicate unless the quoted rule/context combines the
	rows into a single conjunctive requirement.
	SOURCE-EXCERPT FRAGMENT SCOPE: When "Original extracted rule text" is a terse
	fragment, but the "Original source section excerpt" contains the complete
	sentence/table row for that same fragment, the complete source excerpt controls
	the scope of (A). In particular, if the complete source sentence says a
	validity-period limit applies to certificates issued before/after specific
	dates, a generated lint metadata EffectiveDate/IneffectiveDate window matching
	those dates is faithful, not an added narrowing. However, if that same complete
	source sentence contains both an advisory SHOULD/SHOULD NOT threshold and a
	hard MUST/MUST NOT threshold, a single lint that enforces only one severity
	branch does NOT express the whole combined rule.
However, do NOT merge independent neighboring source sentences/rows into (A)
when the "Original extracted rule text" already names one specific branch or
requirement. Source excerpts provide inherited conditions, table headers,
allowed-value rows, and antecedents for words like "otherwise"; they do not
turn the current row into every adjacent rule in the section.
This also applies inside one Markdown table cell or paragraph: if the source
cell/paragraph contains multiple independent RFC2119 sentences, judge the
sentence represented by "Original extracted rule text". Do not transfer an
effective date, severity, or condition from a neighboring RFC2119 sentence
unless that date/condition is in the extracted text itself or is grammatically
the antecedent of that same sentence.
Do not reject (B) merely because the generated zlint metadata omits
EffectiveDate when (A) and the supplied original source context do not state an
effective-date or issuance-date window. Conversely, when (A) or the provided
context explicitly states such a date window, (B) must preserve it through
EffectiveDate/IneffectiveDate metadata or an equivalent CheckApplies condition.
Example: if the extracted rule text is "If the subject field is an empty
SEQUENCE, subjectAltName MUST be marked critical", then code scoped to the
empty-subject branch EXPRESSES that row. Do not reject it for omitting the
neighboring "Otherwise, subjectAltName MUST NOT be marked critical" row.
When an extracted fragment says only "the subjectAltName extension MUST be
critical" but the RFC 5280 §4.1.2.6 source excerpt shows it is the consequent
of the empty-subject/subjectAltName-only naming condition, code scoped to
Subject DN empty plus subjectAltName critical EXPRESSES that fragment.
For table rows such as "Any other qualifier MUST NOT" or "Any other value
MUST NOT", "other" means "outside the values separately permitted by the same
table." A code predicate that allows the table-permitted value(s) and rejects
everything else EXPRESSES that row; do NOT reject it merely because it permits
the explicitly permitted value(s). Conversely, code that forbids all values
does NOT express a complement row if the table explicitly permits one or more
values.
For table-complement rows, the table-permitted set is formed by rows whose
presence/permission column is MUST, SHOULD, MAY, RECOMMENDED, or equivalent
positive permission. Rows whose column is MUST NOT, SHALL NOT, NOT RECOMMENDED,
or equivalent negative/advisory-against wording are not members of the allowed
set. A warning predicate for "Any other value | NOT RECOMMENDED" therefore
EXPRESSES the row when it passes the positively permitted values and warns on
every value outside that set.
When the source section/table title itself names the certificate profile
(for example Root CA, CA Certificate, Subscriber Certificate, or a validation
tier), a final zlint CheckApplies guard matching that profile is faithful
scope, not an added narrowing condition.
For CABF Subscriber validation tiers (Domain Validated, Individual Validated,
Organization Validated, Extended Validation), a guard using the corresponding
Reserved Certificate Policy Identifier is the certificate-encoded discriminator
for that tier. Do not reject it as an arbitrary or extra precondition when the
source profile_scope/section/table title names that tier.
For Organization Validated subscriber subject rows, `domainComponent | MAY |
If present, this field MUST contain a Domain Label from a Domain Name` is a
conditional content rule. A final CheckApplies guard requiring OV subscriber
scope and subject domainComponent presence is faithful; the MAY cell permits
omission, while the MUST clause constrains values only if the field is present.
P-Labels in xn-- form and Non-Reserved LDH labels are Domain Labels for this
purpose.
In CABF §7.1.2 profile tables, "CA Certificate ..." / "Common CA Fields" means
the row is scoped to CA certificates; a final CheckApplies guard "CA
certificates" is faithful for those rows. "OCSP Responder Certificate ..." means
the row is scoped to delegated OCSP responder certificates; a final
CheckApplies guard using zlint's delegated OCSP responder predicate is faithful
for those rows. Do not reject those profile guards merely because the extracted
row text itself is a terse table cell.
Likewise, the TLS Subordinate CA Certificate Profile is represented in zlint
by subordinate CA certificates in the server-auth/TLS profile; a final
CheckApplies guard described that way is faithful to CABF §7.1.2.6.
For the CABF Subscriber (Server) Certificate Profile under §7.1.2.7, zlint's
standard certificate-observable profile guard is `IsSubscriberCert` (non-CA,
non-self-signed subscriber certificate). Do not reject that guard as broader
than "Subscriber (Server)" merely because it does not repeat the profile title
or add a separate serverAuth EKU guard; §7.1.2.7.10 has a separate lintable row
requiring serverAuth in EKU.
When (A) says "Any other qualifier MUST NOT" in a table immediately following
"Permitted policyQualifiers" and the same table has an id-qt-cps MAY row, a
predicate "no policyQualifierId outside id-qt-cps" EXPRESSES that complement
row. The permitted id-qt-cps value is not an exception invented by (B); it is
the value whose complement the word "other" denotes.
If a source table row/cell contains two independent normative clauses, judge
only the clause represented by "Original extracted rule text"; do not require
(B) to also implement a neighboring or omitted clause merely because it appears
elsewhere in the source excerpt and has a different RFC2119 keyword.
When an extracted row is one sentence split from a single source table cell,
use the same-cell local context to resolve anaphora and applicability. A
content/order constraint on an optional field may be implemented as applying
only when that field is present if the same cell/table marks the field MAY or
says "if present"; this is not an added narrowing. Likewise, words such as
"the values", "the fields", or "the Domain Labels" may refer back to the set
defined by the immediately preceding same-cell sentence. Do not reject code for
including that definitional antecedent when it is needed to identify the thing
being ordered or encoded.
The same rule applies to compact formatting sub-tables: when the current row
uses anaphora such as "each" and the immediately surrounding rows define the
referent's type or representation, a predicate may include that definitional
antecedent. Example: if one row says all GeneralNames in a CRL Distribution
Points fullName must be uniformResourceIdentifier and the next row says the
scheme of each must be http, code that requires each such GeneralName to be a
URI and then requires URI scheme http EXPRESSES the scheme row; the URI-type
check is the source-defined antecedent for the word "each", not an invented
extra constraint.
For split domainComponent rows, keep the two clauses separate: a row requiring
the domainComponent fields to be one sequence containing all labels is expressed
by a predicate that checks one contiguous domainComponent block and exact label
coverage; the neighboring row requiring reverse DNS/root-first order is a
separate rule and should not be imported into the first row unless the extracted
text itself includes that order direction.
For AlgorithmIdentifier sections, keep OID rows, parameter rows, and complete
byte-for-byte DER rows separate. A row saying a key is indicated by a named
algorithm OID is expressed by checking that algorithm OID; do not require it
to also check AlgorithmIdentifier parameters unless the extracted row itself
is the parameter row or a full DER byte-for-byte row. Conversely, a parameter
row or full DER row is not expressed by an OID-only check. This remains true
when nearby rows in the same table separately state that parameters MUST be
present/NULL or later give a complete DER encoding: those are sibling
requirements, not hidden sub-clauses of the current OID row.
For exact byte-for-byte AlgorithmIdentifier rows that list DER hex bytes for
one named algorithm, the DER bytes contain that algorithm OID. Code that first
conditions on the same parsed AlgorithmIdentifier OID and then requires the
full DER bytes for that AlgorithmIdentifier EXPRESSES the row; the OID guard
selects the named algorithm row and is not an unrelated narrowing.
For signature AlgorithmIdentifier allowed-encoding rows that list a set of
permitted complete DER encodings for Certificate.signatureAlgorithm and
TBSCertificate.signature, keep the allowed-set row separate from neighboring
or profile/RFC rows requiring the two fields to be byte-for-byte identical to
each other. Code that checks each of those two fields is independently one of
the permitted complete DER encodings EXPRESSES the allowed-set row. Do not
require cross-field equality unless the extracted row itself says the encoded
value is identical to tbsCertificate.signature, and treat code that adds that
equality as stronger than the allowed-set row rather than necessary for it.
For RSA signature AlgorithmIdentifier rows, a CheckApplies guard matching the
RSA signatureAlgorithm OID family (SHA-256/384/512 with RSA or RSASSA-PSS) is
faithful row scope, not an arbitrary narrowing; it prevents applying the RSA
row to ECDSA or other signature algorithms.
For EC SubjectPublicKeyInfo exact-encoding rows keyed by a named curve
(for example P-256/secp256r1, P-384/secp384r1, P-521/secp521r1), the SPKI
AlgorithmIdentifier parameters namedCurve OID is the certificate field that
identifies that named curve. Code that conditions on the same namedCurve OID
and then checks the complete SPKI AlgorithmIdentifier DER expresses that
curve-specific exact-encoding row; it is not the same as using EC point length
as a proxy.
For EC namedCurve value rows such as "For P-256 keys, namedCurve MUST be
secp256r1", a certificate-observable way to identify the P-256/P-384/P-521 key
antecedent is to parse SubjectPublicKeyInfo.subjectPublicKey as an ECPoint and
test whether the point lies on that named NIST curve, then require the matching
namedCurve OID. A malformed point or a point on a different curve is outside
that curve-specific row; other structure/key-validity rules may reject it, but
do not reject this namedCurve row as too narrow merely because it does not treat
malformed ECPoint bytes as a valid P-256/P-384/P-521 key.
In RSA SubjectPublicKeyInfo rows, using the raw subjectPublicKey BIT STRING
as an ASN.1 RSAPublicKey SEQUENCE (modulus and publicExponent) is a faithful
certificate-observable way to identify the "RSA key" antecedent, including
cases where the AlgorithmIdentifier OID is wrong. Do not treat that raw-key
condition as an added precondition for rows about how RSA keys are indicated.
When neighboring rows separately mention parameters present/NULL, the phrase
"AlgorithmIdentifier" in the OID row does not by itself import those parameter
requirements into the current row.
For a CABF RSA SubjectPublicKeyInfo row that says the CA SHALL NOT use a
different algorithm, such as id-RSASSA-PSS, to indicate an RSA key, a predicate
requiring the rsaEncryption algorithm OID for raw RSAPublicKey BIT STRINGs
EXPRESSES the prohibition on different algorithm OIDs; it need not separately
enumerate every forbidden alternative algorithm.
If the same section/table has a header sentence such as "If present, the
Certificate Policies extension ..." or "If present, the
AuthorityInfoAccessSyntax ...", subordinate rows about PolicyInformation,
policyQualifiers, AccessDescription, accessMethod, or accessLocation inherit
that if-present condition. A final zlint lint with CheckApplies requiring that
extension to be present is faithful for those subordinate rows.
For extension subfield rows saying a nested field "MUST NOT be present", a
pass condition that returns true when the containing extension is absent and
false when that subfield appears EXPRESSES the row; the extension has no
nested subfield to violate when absent.
For RFC version rows, "only basic fields are present" means no extensions and
no issuerUniqueID/subjectUniqueID; the standard base TBSCertificate fields are
the basic fields and need not be enumerated in (B).
For RFC 5280 Appendix A ASN.1 module comments, a trailing comment of the form
"-- If present, version MUST ..." belongs to the optional ASN.1 field on the
same or immediately preceding module line, not to the version field itself.
Thus the comments after issuerUniqueID/subjectUniqueID are faithfully scoped by
the presence of those UniqueIdentifier fields, and the comment after extensions
is faithfully scoped by the presence of extensions.
For RFC 5280 CertificatePolicies UserNotice explicitText rows, `Conforming CAs
SHOULD use the UTF8String encoding for explicitText` is advisory and applies
to present UserNotice explicitText values. A lint.Warn when any explicitText
DisplayText CHOICE uses another DisplayText encoding, with Pass when there is
no explicitText or all explicitText values are UTF8String, EXPRESSES the row.
The neighboring MAY IA5String and MUST NOT VisibleString/BMPString rows are
separate normative rows and must not be imported into this SHOULD row.
For CABF CA CertificatePolicies rows whose context says the section has
separate No Policy Restrictions and Policy Restricted profiles, an exact-one
Reserved Certificate Policy Identifier requirement belongs to the Policy
Restricted profile. A CheckApplies condition that excludes anyPolicy is faithful
to that profile signal, not an unrelated narrowing. In that same Policy
Restricted CA profile, the source defines the Reserved Certificate Policy
Identifier by reference to the Subscriber Certificate type directly or
transitively issued by the CA certificate, so the CABF DV/OV/IV/EV reserved
policy OID set expresses that row; do not reject it as the wrong OID set merely
because the certificate being linted is a CA certificate.
For CertificatePolicies policyQualifiers rows whose extracted text is the
single advisory clause "`policyQualifiers` are NOT RECOMMENDED to be present",
keep that advisory presence row separate from the neighboring hard constraint
"If present, MUST contain only permitted policyQualifiers". A zlint warning
when any policyQualifiers are present, and pass when none are present, EXPRESSES
the NOT RECOMMENDED row. A CheckApplies guard requiring the CertificatePolicies
extension to be present is faithful for this subfield row because no
policyQualifiers subfield exists when the extension is absent. Do not call this
a hard prohibition merely because the pass/recommended state has no
policyQualifiers; lint.Warn is the advisory representation of "not
recommended", and the permitted-qualifier allow-list is a separate row.
For CABF rules that prohibit certificate Domain Names ending in an IP Reverse
Zone Suffix, the concrete DNS reverse-zone suffixes are in-addr.arpa and
ip6.arpa. A predicate that checks certificate Domain Names against those two
suffixes expresses the source phrase "IP Reverse Zone Suffix".
For CABF Subscriber subjectAltName rows about the FQDN or wildcard FQDN portion
being composed entirely of P-Labels or Non-Reserved LDH Labels joined by U+002E,
a predicate that applies the same label-composition test to each SAN dNSName
and, for names beginning "*.", to the portion after the wildcard label,
EXPRESSES the row.
For CABF §7.1.4.3 Subscriber Certificate Common Name Attribute bullets, the
phrase "the value" refers to the subject commonName attribute value being
encoded. The preceding sentence saying commonName, if present, is one SAN value
is a separate row-level requirement. Do not require an IPv4 textual-encoding
bullet to also prove SAN membership or to check SAN iPAddress OCTET STRINGs;
checking the subject commonName string's RFC 3986 IPv4Address dotted-decimal
syntax expresses that bullet.
Do not reject the IPv4 bullet as overbroad merely because the lint does not
first prove the separate "commonName is one value from SAN" sentence; a
certificate with a non-SAN commonName can violate that separate row and still
be evaluated for whether its commonName IPv4 text uses the required textual
encoding.
For RFC 5280 Appendix B, the sign-bit sentence immediately follows "CAs MUST
force the serialNumber to be a non-negative integer"; therefore "the INTEGER
value" in that sentence is the certificate serialNumber INTEGER, not every
INTEGER anywhere in a certificate.
For ASN.1 module comments inside an extension value type, a final zlint lint
may use CheckApplies(extension present) before checking that extension's
subfields; no extension value exists when the extension is absent.
For ASN.1 module comments under CRL structures such as CertificateList,
TBSCertList, revokedCertificates, or crlExtensions, a generated certificate lint
does NOT express the rule if it instead checks certificate fields.

{profile_scope_block}
=== (A) RULE (original normative text) ===
{rule_text}

=== (B) CODE-DERIVED SEMANTICS (what the generated Execute function actually checks) ===
{code_sem}

=== DECIDE ===

  EXPRESSES         -> (B) captures the FULL meaning of (A). Same field(s),
                       same direction, every sub-clause encoded, no extra
                       preconditions beyond what (A) states.

  DOES_NOT_EXPRESS  -> ANY of: drops a sub-clause, reverses direction,
                       targets wrong field/extension/bit, narrows or widens
                       constraint, adds unjustified precondition.

EXAMPLES:
  (A) "stateOrProvinceName MUST be present in subject DN."
  (B) "checks Subject.Province is non-empty" -> EXPRESSES.
  (A) "SerialNumber MUST be a non-negative integer."
  (B) "checks SerialNumber is present" -> DOES_NOT_EXPRESS (sub-clause truncation).
  (A) "CommonName MUST use UTF8String or PrintableString, max length 64."
  (B) "checks CN length == 64" -> DOES_NOT_EXPRESS (drops encoding clause).

Return ONLY a JSON object, no prose. The verdict MUST be exactly
"EXPRESSES" or "DOES_NOT_EXPRESS" (with the underscore).

  {{
    "verdict": "EXPRESSES" | "DOES_NOT_EXPRESS",
    "missing_or_wrong": "<short phrase or 'none'>",
    "why": "<one short sentence>"
  }}
"""


def judge_expresses(rule_text: str, code_sem: str, *,
                    profile_scope: str | None = None,
                    max_tokens: int = 500) -> dict:
    """Returns dict: verdict, missing_or_wrong, why, raw.

    profile_scope: when the rule is from a named certificate-profile section,
    pass the profile title so added preconditions matching that profile's
    certificate type are treated as faithful (not spurious added preconditions).
    """
    if profile_scope:
        psb = (
            f"\nRULE CONTEXT: rule (A) was extracted from a standards section "
            f'or table titled "{profile_scope}". Treat this title as implicit '
            "background for interpreting terse table rows and omitted subjects "
            "(for example, a Common Name Attribute table row is about commonName). "
            "This is the row-level predicate gate, so (B) does not need to "
            "restate the profile scope in its prose; the final in-tree zlint "
            "shipping gate separately checks CheckApplies/profile scope. Do "
            "not mark (B) DOES_NOT_EXPRESS solely because it omits the profile "
            "title while otherwise checking the right predicate. "
            "When the title is a certificate-profile title, a precondition in "
            "(B) that matches that profile EXPRESSES the scope faithfully and is "
            "NOT an extra narrowing condition. Examples: Root CA profile -> Root "
            "CA guard; Subscriber Certificate profile -> Subscriber certificate "
            "guard; EV/OV/IV/DV profile -> matching reserved certificate policy "
            "OID guard; Precertificate Signing / Precertificate profile -> "
            "PreCertificateSigningCertificateEKU guard; TLS/Subordinate/CA "
            "profile -> CA/Subordinate-CA guard. Reject a scope guard only when "
            "it is incompatible with the named context or adds an unrelated "
            "condition not entailed by that context. If RULE CONTEXT explicitly "
            "names a standard OID or identifier, use that identifier to interpret "
            "terse or truncated table cells in (A); do not ignore it merely "
            "because the extracted row text is incomplete. If RULE CONTEXT is an "
            "RFC field section title such as Issuer, Subject, Validity, or "
            "Authority Information Access, treat that field title as implicit "
            "scope for omitted subjects in (A). Do not reinterpret an Issuer or "
            "Subject section row as a generic all-Name rule unless (A) explicitly "
            "states that broader generic scope.\n"
        )
    else:
        psb = ""
    _rt = (rule_text or "")[:3000]
    # Keep the full mechanical semantics for table-driven conjunctions. A
    # 1000-character cutoff can terminate an otherwise complete predicate
    # halfway through its attribute/encoding clauses and make the judge report
    # a false DOES_NOT_EXPRESS. The generated summaries are deterministic and
    # bounded by the closed DSL tree; retain enough room for the largest
    # source-table expansion without inventing or dropping clauses.
    _cs = (code_sem or "")[:16000]
    prompt = (JUDGE_PROMPT
              .replace("{profile_scope_block}", psb)
              .replace("{rule_text}", _rt)
              .replace("{code_sem}", _cs))
    raw = call_llm(prompt, max_tokens=max_tokens, model="gpt-5.4")
    if isinstance(raw, str) and raw.startswith("__ERROR__"):
        return {"verdict": "ERROR", "missing_or_wrong": "",
                "why": raw[:200], "raw": raw[:200]}
    obj = parse_json_block(raw) or {}
    verdict_raw = (obj.get("verdict") or "").strip()
    v_norm = verdict_raw.upper().replace(" ", "_").replace("-", "_")
    while "__" in v_norm:
        v_norm = v_norm.replace("__", "_")
    if v_norm.startswith("DOES_NOT") or v_norm.startswith("NOT_") or v_norm in ("NONE", "PARTIAL"):
        verdict = "DOES_NOT_EXPRESS"
    elif v_norm.startswith("EXPRESS") or v_norm in ("FULL",):
        verdict = "EXPRESSES"
    else:
        verdict = "PARSE_ERROR"
    return {
        "verdict":          verdict,
        "verdict_raw":      verdict_raw,
        "missing_or_wrong": (obj.get("missing_or_wrong") or "")[:200],
        "why":              (obj.get("why") or "")[:300],
        "raw":              (raw or "")[-300:],
    }


# ============================================================================
# judge_vote — denoised majority vote (K x judge_expresses)
# ============================================================================
from concurrent.futures import ThreadPoolExecutor


def judge_vote(rule_text: str, code_sem: str, *, k: int = 5,
               profile_scope: str | None = None,
               inner_workers: int = 5) -> dict:
    """Run judge_expresses k times; return majority verdict + tally.

    Ties break to DOES_NOT_EXPRESS (conservative -- never ship on a tie).
    Returns {verdict, n_expresses, n_dne, n_err, k, agreement, sample_why}.
    """
    def one(_):
        try:
            return judge_expresses(rule_text, code_sem,
                                   profile_scope=profile_scope)
        except Exception as e:
            return {"verdict": "ERROR", "why": str(e)[:120]}

    with ThreadPoolExecutor(max_workers=min(inner_workers, k)) as ex:
        votes = list(ex.map(one, range(k)))
    ne  = sum(1 for v in votes if v.get("verdict") == "EXPRESSES")
    nd  = sum(1 for v in votes if v.get("verdict") == "DOES_NOT_EXPRESS")
    nerr = sum(1 for v in votes
               if v.get("verdict") not in ("EXPRESSES", "DOES_NOT_EXPRESS"))
    decided = ne + nd
    if decided == 0:
        sample_why = ""
        for v in votes:
            sample_why = v.get("why") or v.get("missing_or_wrong") or v.get("raw") or ""
            if sample_why:
                break
        return {
            "verdict": "ERROR",
            "n_expresses": ne, "n_dne": nd, "n_err": nerr,
            "k": k,
            "agreement": 0.0,
            "sample_why": sample_why[:200],
        }
    verdict = "EXPRESSES" if ne > nd else "DOES_NOT_EXPRESS"
    sample_why = ""
    for v in votes:
        if v.get("verdict") == verdict and v.get("why"):
            sample_why = v["why"]; break
    if not sample_why:
        for v in votes:
            if v.get("missing_or_wrong"):
                sample_why = v["missing_or_wrong"]; break
    return {
        "verdict":    verdict,
        "n_expresses": ne, "n_dne": nd, "n_err": nerr,
        "k": k,
        "agreement":  (max(ne, nd) / decided) if decided else 0.0,
        "sample_why": sample_why[:200],
    }


# ============================================================================
# Self-test
# ============================================================================

if __name__ == "__main__":
    print("=== judge_expresses smoke-test ===")
    cases = [
        ("stateOrProvinceName MUST be present in subject DN.",
         "checks Subject.Province is non-empty",
         "EXPRESSES"),
        ("SerialNumber MUST be a non-negative integer.",
         "checks SerialNumber is present",
         "DOES_NOT_EXPRESS"),
        ("CommonName MUST use UTF8String or PrintableString, max length 64.",
         "checks CN length == 64",
         "DOES_NOT_EXPRESS"),
    ]
    for rule, code, expected in cases:
        r = judge_expresses(rule, code)
        ok = "OK" if r["verdict"] == expected else "MISMATCH"
        print(f"[{ok}] expected={expected} got={r['verdict']}  why={r['why'][:60]}")

    print("\n=== judge_synonymy (legacy extraction-side API) ===")
    j = judge_synonymy(
        a_text="The serial number MUST be a positive integer.",
        candidates=[
            {"rule_id": "demo_full",    "text": "Serial number MUST be greater than zero."},
            {"rule_id": "demo_partial", "text": "Serial number MUST NOT exceed 20 octets."},
            {"rule_id": "demo_none",    "text": "The extension MUST be marked critical."},
        ],
    )
    print(f"  verdict = {j['verdict']}, picks = {len(j['picks'])}")
    for p in j["picks"]:
        print(f"    [{p['index']}] {p['verdict']}  -> {p['candidate']['rule_id']}: {p['why']}")
