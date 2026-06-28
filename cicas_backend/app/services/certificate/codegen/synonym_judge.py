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
  - LLM:             Qwen/Qwen3-8B, temperature=0, reasoning_level=off
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

LLM_MODEL = os.environ.get("LLM_MODEL", "THUDM/GLM-Z1-9B-0414")
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
    """Call the unified ai.ailink1.com OpenAI-compatible endpoint (gpt-5.5).
    A system message is mandatory for this endpoint."""
    payload = {
        "model": AILINK_MODEL,
        "messages": [{"role": "system", "content": AILINK_SYSTEM},
                     {"role": "user", "content": prompt}],
        "max_tokens": max_tokens,
        "temperature": temperature,
    }
    for attempt in range(6):
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
    """Call the unified experiment LLM (ai.ailink1.com / gpt-5.5) with retries;
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

DN BYTE EQUALITY: c.RawSubject and c.RawIssuer are DER-encoded distinguished
names. A check "bytes.Equal(c.RawSubject, c.RawIssuer)" directly encodes
"subject DN MUST be byte-for-byte identical to issuer DN".

SEVERITY EQUIVALENCE: lint.Error <=> MUST/MUST NOT/SHALL/PROHIBITED;
lint.Warn <=> SHOULD/SHOULD NOT/RECOMMENDED; lint.Notice <=> MAY/OPTIONAL.
A code returning lint.Warn for a SHOULD rule IS faithful.

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
            f"\nPROFILE SCOPE: rule (A) is from certificate-profile section "
            f'"{profile_scope}". A precondition in (B) restricting the check to '
            "that profile's certificate type (Root CA / Subscriber / etc.) "
            "EXPRESSES the rule's scope FAITHFULLY.\n"
        )
    else:
        psb = ""
    _rt = (rule_text or "")[:1500]
    _cs = (code_sem or "")[:1000]
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
    verdict = "EXPRESSES" if ne > nd else "DOES_NOT_EXPRESS"
    decided = ne + nd
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
