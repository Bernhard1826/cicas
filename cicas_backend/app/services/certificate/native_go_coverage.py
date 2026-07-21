"""Auditable native-zlint coverage adjudication from actual Go source.

The legacy coverage matcher compares an extracted requirement IR with a lossy
reverse IR summary of native lints.  That summary cannot faithfully retain
boolean guards or the relation between ``CheckApplies`` and ``Execute``.  This
module instead supplies the authoritative source requirement and the complete
native Go decision bodies to a strict coverage judge.

``full`` has a one-way meaning: every certificate violating the requirement
must be in the named native lint's applicable domain and must receive a
non-Pass result.  Related checks and narrower checks are not full coverage.
No rule IDs, lint IDs, or specification-specific pairings are encoded here.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

from app.core.config import settings
from app.utils.llm_client import LLMClient


_IGNORED_TOKENS = {
    "the", "and", "for", "with", "that", "this", "from", "into", "must", "shall",
    "should", "not", "certificate", "certificates", "extension", "extensions", "present",
    "absence", "field", "value", "values", "lint", "check", "return", "true", "false",
    "util", "cert", "certificate", "x509", "status", "error", "pass", "warning",
}
_NAME_RE = re.compile(r'Name:\s*"([a-z][a-z0-9_]+)"')
_DESCRIPTION_RE = re.compile(r'Description:\s*"([^"]*)"')
_CITATION_RE = re.compile(r'Citation:\s*"([^"]*)"')
_SOURCE_RE = re.compile(r"Source:\s*lint\.([A-Za-z0-9_]+)")


def _balanced_body(text: str, start: int) -> str:
    """Return a brace-balanced Go function body beginning at ``start``."""
    brace = text.find("{", start)
    if brace < 0:
        return ""
    depth = 0
    for pos in range(brace, len(text)):
        if text[pos] == "{":
            depth += 1
        elif text[pos] == "}":
            depth -= 1
            if depth == 0:
                return text[start:pos + 1]
    return text[start:]


def _go_method(text: str, method: str) -> str:
    match = re.search(rf"func\s*\([^)]*\)\s*{re.escape(method)}\s*\(", text)
    return _balanced_body(text, match.start()) if match else ""


def _go_functions(text: str) -> dict[str, str]:
    """Index free and receiver Go functions by unqualified name."""
    out: dict[str, str] = {}
    pattern = re.compile(r"(?m)^func\s+(?:\([^)]*\)\s*)?([A-Za-z_][A-Za-z0-9_]*)\s*\(")
    for match in pattern.finditer(text):
        out.setdefault(match.group(1), _balanced_body(text, match.start()))
    return out


def _called_function_names(text: str) -> set[str]:
    return {
        match.group(1)
        for match in re.finditer(r"(?:\butil\.)?([A-Za-z_][A-Za-z0-9_]*)\s*\(", text)
        if match.group(1) not in {"if", "for", "switch", "return", "make", "len"}
    }


def _comment_context(text: str, anchor: int) -> str:
    """Keep the nearby normative comment; it often documents code intent."""
    start = text.rfind("/************************************************", 0, anchor)
    if start < 0:
        start = max(0, anchor - 2500)
    return text[start:anchor].strip()[-4000:]


def _tokens(*values: Any) -> set[str]:
    raw = " ".join(str(value or "") for value in values)
    raw = re.sub(r"([a-z])([A-Z])", r"\1 \2", raw)
    raw = raw.replace("_", " ").replace(".", " ").replace("/", " ")
    return {
        value.lower()
        for value in re.findall(r"[A-Za-z][A-Za-z0-9]{2,}|\d+(?:\.\d+){2,}", raw)
        if value.lower() not in _IGNORED_TOKENS
    }


def _parse_ir(raw: Any) -> dict[str, Any]:
    if isinstance(raw, dict):
        value = raw
    else:
        try:
            value = json.loads(raw) if raw else {}
        except (TypeError, json.JSONDecodeError):
            return {}
    if isinstance(value, dict) and isinstance(value.get("ir"), dict):
        return value["ir"]
    return value if isinstance(value, dict) else {}


def _function_line_numbers(text: str, method: str) -> str:
    match = re.search(rf"func\s*\([^)]*\)\s*{re.escape(method)}\s*\(", text)
    if not match:
        return "unknown"
    return str(text.count("\n", 0, match.start()) + 1)


@dataclass(frozen=True)
class NativeLint:
    name: str
    description: str
    citation: str
    source: str
    path: Path
    code: str
    code_sha256: str
    supporting_go: str = ""

    @property
    def semantic_source(self) -> str:
        init_anchor = self.code.find("func init()")
        check = _go_method(self.code, "CheckApplies")
        execute = _go_method(self.code, "Execute")
        return "\n\n".join(
            part for part in (
                _comment_context(self.code, init_anchor if init_anchor >= 0 else 0),
                check,
                execute,
                self.supporting_go,
            ) if part
        )

    def prompt_block(self) -> str:
        relative = self.path.as_posix()
        return (
            f"NATIVE LINT: {self.name}\n"
            f"FILE: {relative}\n"
            f"SHA256: {self.code_sha256}\n"
            f"DESCRIPTION: {self.description}\n"
            f"CITATION: {self.citation}\n"
            f"CHECKAPPLIES_LINE: {_function_line_numbers(self.code, 'CheckApplies')}\n"
            f"EXECUTE_LINE: {_function_line_numbers(self.code, 'Execute')}\n"
            "ACTUAL GO:\n```go\n"
            f"{self.semantic_source}\n```"
        )


class NativeGoCoverageJudge:
    """Compare source requirements to bundled native zlint Go implementations."""

    _PRIMARY_PROMPT = """You are auditing whether native zlint code already covers a PKI requirement.

Coverage is a SET-INCLUSION claim over certificate findings, not topical similarity:
return FULL only if every certificate that violates the source requirement will
fall inside the native lint's CheckApplies domain and make its Execute method
return a non-Pass result.  A native check may be stricter/broader and still be
FULL.  A check that misses any permitted requirement violation is PARTIAL or
NONE.  Never infer behavior not present in the Go code.
For this experiment, every zlint status other than ``Pass`` is detection:
``Warn``, ``Notice``, ``Error``, and ``Fatal`` all count as non-Pass.  Do not
discard a warning-level lint when proving coverage.

First normalize the requirement into a violation predicate before comparing Go.
For example, ``if A is absent, B MUST be present`` is violated exactly when
``A is absent AND B is absent``; a native lint that errors exactly when both
are absent is FULL, not partial.  Similarly, ``X MUST be present`` is violated
by ``X absent``.  Preserve every stated scope/precondition.

The requirement IR is closed for this per-rule decision. Do not add another
row from the same profile as an implicit precondition. A certificate may
violate several profile requirements at once; failure of a separate required
field does not remove it from this rule's stated scope.

More than one native lint may jointly provide FULL coverage.  You may return a
deterministic ``name1+name2`` union only when their combined non-Pass sets
cover every requirement violation; do not use a union merely because checks
are related.

Read the authoritative requirement text and source-section context.  Then read
each candidate's actual Go.  Check preconditions, field, polarity, values,
boolean AND/OR, artifact type, and result severity.  A table fragment is not
enough: retain any condition stated in the source-section context.

REQUIREMENT\n{requirement}\n
SOURCE SECTION (authoritative, possibly truncated)\n{source_section}\n
CANDIDATES\n{candidates}\n
Return ONLY JSON:
{{"verdict":"full"|"partial"|"none","lint":"<exact candidate name, or name1+name2 union, or null>",
"proof":"<set-inclusion argument tied to actual Go paths>",
"counterexample":"<a requirement-violating certificate missed by native lint, or null>",
"evidence":["<file:line and behavior>"]}}
"""

    _SKEPTIC_PROMPT = """You are the skeptical second reviewer of a zlint coverage claim.

The claimed relationship is FULL only if the native Go lint or explicitly
named lint union catches every
certificate that violates the authoritative requirement.  Look specifically
for an omitted precondition, a narrower CheckApplies guard, a reversed boolean
condition, missing disjunct, different field/value, or a Pass path.  Do not
trust metadata or the first review; decide from the source requirement and
actual Go code below.  For a union, a certificate is detected when *any* member
returns non-Pass.  Test every claimed counterexample against every union member;
do not reject a union merely because one member has a narrower CheckApplies.
``Warn``, ``Notice``, ``Error``, and ``Fatal`` are all non-Pass detections;
warning-level findings count in a union exactly as error-level findings do.

Before deciding, evaluate every negated helper literally from its supplied Go
body and state the resulting truth table in ``proof``.  For example, if the
helper returns ``len(Name.Names) >= 1``, then its negation is true exactly when
``len(Name.Names) == 0``.  Never reverse a ``!`` condition by prose intuition.
For a claimed union, partition the requirement violation predicate into its
branches and test each branch against *all* union members.

REQUIREMENT\n{requirement}\n
SOURCE SECTION\n{source_section}\n
CLAIMED NATIVE LINT OR UNION\n{candidate}\n
Return ONLY JSON:
{{"verdict":"full"|"partial"|"none","proof":"<why all violations are caught, or why not>",
"counterexample":"<missed violating certificate, or null>",
"evidence":["<file:line and behavior>"]}}
"""

    _COUNTEREXAMPLE_REVIEW_PROMPT = """You are correcting a proposed non-coverage verdict using formal Boolean reasoning.

The primary reviewer may have confused an implication with a different rule or
may have considered only one lint where a pair jointly covers the requirement.
Independently formalize the source requirement's *violation predicate*, then
test the primary counterexample against the actual Go paths.  In particular,
``if A is absent, B MUST be present`` has violation predicate
``A absent AND B absent``.  A native lint that errors on that conjunction is
FULL coverage.  If no single lint is full, test whether a minimal union of
named candidates is full.  Return FULL only for a proven set inclusion.
Any status other than ``Pass`` is a detection for this coverage definition,
including ``Warn`` and ``Notice``; do not exclude warning-level lints.

Treat the requirement IR precondition as closed. Do not assume that satisfying
some other mandatory table row is an additional precondition of this rule:
one certificate may violate both rows simultaneously.

REQUIREMENT\n{requirement}\n
SOURCE SECTION\n{source_section}\n
PRIMARY REVIEW (not authoritative)\n{primary}\n
ACTUAL CANDIDATES\n{candidates}\n
Return ONLY JSON:
{{"verdict":"full"|"partial"|"none","lint":"<candidate or name1+name2 union or null>",
"proof":"<formal violation predicate and Go-path argument>",
"counterexample":"<a real missed requirement violation, or null>",
"evidence":["<file:line and behavior>"]}}
"""

    _NONFULL_TIEBREAKER_PROMPT = """You are resolving an internally inconsistent zlint coverage review.

The selected native lint was already independently argued to be FULL, but the
skeptical reviewer returned a non-FULL label without a concrete counterexample.
Decide from the authoritative requirement and actual Go only.

For PARTIAL or NONE, you MUST provide one concrete certificate satisfying every
IR/source requirement precondition and violating the requirement, then identify
the exact CheckApplies or Execute Pass path by which the selected native lint
misses it. If you cannot provide such a counterexample, return FULL and give
the set-inclusion proof. Do not treat a native lint's broader error set as a
failure: FULL only requires every requirement violation to be detected.
Detection means any non-Pass zlint status, including ``Warn`` and ``Notice``.

REQUIREMENT\n{requirement}\n
SOURCE SECTION\n{source_section}\n
SELECTED NATIVE LINT OR UNION\n{candidate}\n
PRIOR REVIEWS\n{reviews}\n
Return ONLY JSON:
{{"verdict":"full"|"partial"|"none","proof":"<formal argument>",
"counterexample":"<concrete missed requirement violation, or null>",
"evidence":["<file:line and behavior>"]}}
"""

    _COUNTEREXAMPLE_VALIDATION_PROMPT = """You are validating a proposed non-coverage counterexample against actual zlint Go.

Coverage is one-way set inclusion: a native lint may flag certificates beyond
the source requirement and still be FULL, as long as every source violation is
flagged. Independently formalize the requirement violation predicate and test
the prior review's proposed counterexample against EVERY listed native lint.
The requirement IR precondition is closed; do not borrow another profile row
to remove a certificate that violates this rule from scope.

Any ``Warn``, ``Notice``, ``Error``, or ``Fatal`` outcome is non-Pass and
therefore detects the certificate for this coverage experiment.

Return PARTIAL or NONE only with a concrete certificate that satisfies every
requirement precondition, violates the requirement, and reaches a Pass path in
every listed candidate. If any listed lint catches the proposed counterexample,
it is not a counterexample. Return FULL only with an explicit set-inclusion
argument over the actual Go paths.

REQUIREMENT\n{requirement}\n
SOURCE SECTION\n{source_section}\n
PRIOR NON-FULL REVIEW\n{review}\n
CANDIDATES TO TEST\n{candidates}\n
Return ONLY JSON:
{{"verdict":"full"|"partial"|"none","lint":"<candidate or name1+name2 union, or null>",
"proof":"<set-inclusion or concrete missed-path argument>",
"counterexample":"<a missed violating certificate, or null>",
"evidence":["<file:line and behavior>"]}}
"""

    def __init__(self, zlint_root: Path | str, llm_client: LLMClient | None = None):
        self.zlint_root = Path(zlint_root)
        self.lints_root = self.zlint_root / "v3" / "lints"
        self.llm_client = llm_client or LLMClient(
            model=settings.llm_model,
            temperature=0,
            max_tokens=1400,
        )
        self._lints: list[NativeLint] | None = None

    def _util_functions(self) -> dict[str, str]:
        source = "\n".join(
            path.read_text(encoding="utf-8", errors="replace")
            for path in sorted((self.zlint_root / "v3" / "util").glob("*.go"))
            if not path.name.endswith("_test.go")
        )
        return _go_functions(source)

    @staticmethod
    def _supporting_go(code: str, util_functions: dict[str, str]) -> str:
        """Expand direct helper calls so Go semantics remain source-auditable."""
        check = _go_method(code, "CheckApplies")
        execute = _go_method(code, "Execute")
        calls = _called_function_names(check + "\n" + execute)
        local_functions = _go_functions(code)
        bodies: list[str] = []
        for name in sorted(calls):
            body = local_functions.get(name) or util_functions.get(name)
            if body and name not in {"CheckApplies", "Execute"}:
                bodies.append(body)
        return "\n\n".join(bodies)

    def load_lints(self) -> list[NativeLint]:
        if self._lints is not None:
            return self._lints
        lints: list[NativeLint] = []
        util_functions = self._util_functions()
        for path in sorted(self.lints_root.rglob("*.go")):
            if path.name.endswith("_test.go"):
                continue
            code = path.read_text(encoding="utf-8", errors="replace")
            if "RegisterCertificateLint(" not in code or "cicasgen_" in code:
                continue
            names = _NAME_RE.findall(code)
            if not names:
                continue
            description = (_DESCRIPTION_RE.search(code).group(1)
                           if _DESCRIPTION_RE.search(code) else "")
            citation = (_CITATION_RE.search(code).group(1)
                        if _CITATION_RE.search(code) else "")
            source = (_SOURCE_RE.search(code).group(1)
                      if _SOURCE_RE.search(code) else "")
            digest = hashlib.sha256(code.encode("utf-8")).hexdigest()
            for name in names:
                lints.append(NativeLint(
                    name, description, citation, source, path, code, digest,
                    self._supporting_go(code, util_functions),
                ))
        self._lints = lints
        return lints

    def rank_candidates(self, rule: dict[str, Any], limit: int = 24) -> list[NativeLint]:
        """Rank all native certificate lints without source or rule-id pairings."""
        ir = _parse_ir(rule.get("ir") or rule.get("ir_data"))
        # Retrieval must be driven by the assertion and structured IR, not the
        # entire section.  A long SAN section, for example, would otherwise bury
        # an exact "empty subject + critical SAN" lint beneath unrelated SAN
        # syntax lints.  The full source section is still supplied to the judge.
        rule_tokens = _tokens(
            rule.get("text"), rule.get("section"), ir.get("subject"),
            ir.get("predicate"), ir.get("constraint"), ir.get("precondition"),
        )
        scored: list[tuple[float, str, NativeLint]] = []
        for native in self.load_lints():
            metadata_tokens = _tokens(native.name, native.description, native.citation)
            code_tokens = _tokens(native.semantic_source)
            metadata_overlap = len(rule_tokens & metadata_tokens)
            code_overlap = len(rule_tokens & code_tokens)
            union = len(rule_tokens | metadata_tokens) or 1
            # Exact OID / section-token overlap naturally outranks loose prose.
            score = metadata_overlap * 9 + code_overlap * 2 + metadata_overlap / union
            if str(rule.get("section") or "") and str(rule.get("section")) in native.citation:
                score += 8
            scored.append((score, native.name, native))
        scored.sort(key=lambda item: (-item[0], item[1]))
        ranked = [native for _, _, native in scored[:limit]]

        # When auditing a previously persisted "covered" claim, the claimed
        # native lint must be available to the judge even if token retrieval
        # would not rank it in the top-K. This seeds the candidate set only; it
        # does not force a FULL verdict.
        claimed_names = [
            name.strip()
            for name in str(rule.get("lint_name") or "").split("+")
            if name.strip()
        ]
        if not claimed_names:
            return ranked
        by_name = {native.name: native for native in self.load_lints()}
        seeded: list[NativeLint] = []
        seen: set[str] = set()
        for name in claimed_names:
            native = by_name.get(name)
            if native is not None and native.name not in seen:
                seeded.append(native)
                seen.add(native.name)
        for native in ranked:
            if native.name not in seen:
                seeded.append(native)
                seen.add(native.name)
        return seeded

    @staticmethod
    def _parse_json(raw: str) -> dict[str, Any]:
        match = re.search(r"\{.*\}", raw or "", flags=re.DOTALL)
        if not match:
            return {}
        try:
            value = json.loads(match.group(0))
        except json.JSONDecodeError:
            return {}
        return value if isinstance(value, dict) else {}

    @staticmethod
    def _requirement_block(rule: dict[str, Any]) -> str:
        ir = _parse_ir(rule.get("ir") or rule.get("ir_data"))
        return "\n".join((
            f"rule_id: {rule.get('id')}",
            f"source: {rule.get('source')}",
            f"section: {rule.get('section')}",
            f"text: {rule.get('text') or ir.get('rule_text') or ''}",
            f"subject: {ir.get('subject') or ''}",
            f"obligation: {ir.get('obligation') or ''}",
            f"predicate: {ir.get('predicate') or ''}",
            f"constraint: {json.dumps(ir.get('constraint'), ensure_ascii=False)}",
            f"precondition: {json.dumps(ir.get('precondition'), ensure_ascii=False)}",
            "certificate_type semantics: subscriber means a non-CA, non-self-signed certificate; "
            "ca means a CA certificate; root means a self-signed CA certificate. "
            "A proposed counterexample must satisfy these IR preconditions literally.",
        ))

    @staticmethod
    def _selected_candidates(raw_name: Any, candidates: list[NativeLint]) -> tuple[list[str], list[NativeLint]]:
        names = [name.strip() for name in str(raw_name or "").split("+") if name.strip()]
        by_name = {candidate.name: candidate for candidate in candidates}
        selected = [by_name[name] for name in names if name in by_name]
        if not names or len(selected) != len(names) or len(set(names)) != len(names):
            return [], []
        return names, selected

    @staticmethod
    def _has_counterexample(review: dict[str, Any]) -> bool:
        value = review.get("counterexample")
        if not isinstance(value, str):
            return False
        text = value.strip().lower()
        if text in {"", "none", "null", "n/a"}:
            return False
        # A response that says its own example is caught, or that no miss
        # exists, is not an actionable counterexample regardless of its label.
        nonexamples = (
            "no missed", "no miss", "no counterexample", "is caught",
            "would be caught", "caught by", "not a missed",
        )
        return not any(phrase in text for phrase in nonexamples)

    async def judge(
        self,
        rule: dict[str, Any],
        *,
        candidate_limit: int = 24,
        require_skeptic: bool = True,
    ) -> dict[str, Any]:
        candidates = self.rank_candidates(rule, limit=candidate_limit)
        requirement = self._requirement_block(rule)
        source_section = str(rule.get("source_section") or "(source section unavailable)")[:12000]
        if not candidates:
            return {
                "has_coverage": False, "verdict": "none", "lint_name": None,
                "reasoning": "No native certificate lint candidate was available.", "fields": {},
                "n_candidates": 0, "match_method": "native_go_two_pass", "audit": {},
            }

        prompt = self._PRIMARY_PROMPT.format(
            requirement=requirement,
            source_section=source_section,
            candidates="\n\n".join(candidate.prompt_block() for candidate in candidates),
        )
        try:
            primary_raw = await asyncio.to_thread(
                self.llm_client.generate, prompt, max_tokens_override=1400, timeout_override=300.0,
            )
        except Exception as exc:
            return {
                "has_coverage": False, "verdict": "none", "lint_name": None,
                "reasoning": f"native Go primary judge failed: {exc}", "fields": {},
                "n_candidates": len(candidates), "match_method": "native_go_two_pass", "audit": {},
            }
        primary = self._parse_json(primary_raw)
        initial_primary = primary
        verdict = str(primary.get("verdict") or "none").lower()
        selected_names, selected = self._selected_candidates(primary.get("lint"), candidates)
        repair: dict[str, Any] = {}
        counterexample_validation: dict[str, Any] = {}
        if verdict != "full" or not selected:
            repair_prompt = self._COUNTEREXAMPLE_REVIEW_PROMPT.format(
                requirement=requirement,
                source_section=source_section,
                primary=json.dumps(primary, ensure_ascii=False),
                candidates="\n\n".join(candidate.prompt_block() for candidate in candidates),
            )
            try:
                repair_raw = await asyncio.to_thread(
                    self.llm_client.generate, repair_prompt, max_tokens_override=1400, timeout_override=300.0,
                )
                repair = self._parse_json(repair_raw)
            except Exception as exc:
                repair = {"verdict": "none", "proof": f"counterexample review failed: {exc}"}
            repair_names, repair_selected = self._selected_candidates(repair.get("lint"), candidates)
            if str(repair.get("verdict") or "none").lower() == "full" and repair_selected:
                primary = repair
                selected_names, selected = repair_names, repair_selected
                verdict = "full"
            else:
                # A non-full counterexample must survive every candidate it
                # names. This independent validation catches the invalid
                # inference that a broader native error set is only partial.
                if repair_selected:
                    validation_prompt = self._COUNTEREXAMPLE_VALIDATION_PROMPT.format(
                        requirement=requirement,
                        source_section=source_section,
                        review=json.dumps(repair, ensure_ascii=False),
                        candidates="\n\n".join(item.prompt_block() for item in repair_selected),
                    )
                    try:
                        validation_raw = await asyncio.to_thread(
                            self.llm_client.generate, validation_prompt,
                            max_tokens_override=1400, timeout_override=300.0,
                        )
                        counterexample_validation = self._parse_json(validation_raw)
                    except Exception as exc:
                        counterexample_validation = {
                            "verdict": "none",
                            "proof": f"counterexample validation failed: {exc}",
                        }
                    validation_names, validation_selected = self._selected_candidates(
                        counterexample_validation.get("lint"), candidates
                    )
                    if (str(counterexample_validation.get("verdict") or "none").lower() == "full"
                            and validation_selected):
                        primary = counterexample_validation
                        selected_names, selected = validation_names, validation_selected
                        verdict = "full"
                if verdict != "full" or not selected:
                    return {
                        "has_coverage": False, "verdict": verdict if verdict in {"partial", "none"} else "none",
                        "lint_name": None, "reasoning": str(repair.get("proof") or repair.get("counterexample")
                                                              or primary.get("proof") or primary.get("counterexample") or "")[:2000],
                        "fields": {}, "n_candidates": len(candidates), "match_method": "native_go_two_pass",
                        "audit": {"primary": initial_primary, "counterexample_review": repair,
                                  "counterexample_validation": counterexample_validation,
                                  "candidate_names": [item.name for item in candidates]},
                    }

        if verdict != "full" or not selected:
            return {
                "has_coverage": False, "verdict": verdict if verdict in {"partial", "none"} else "none",
                "lint_name": None, "reasoning": str(primary.get("proof") or primary.get("counterexample") or "")[:2000],
                "fields": {}, "n_candidates": len(candidates), "match_method": "native_go_two_pass",
                "audit": {"primary": initial_primary, "counterexample_review": repair,
                          "counterexample_validation": counterexample_validation,
                          "candidate_names": [item.name for item in candidates]},
            }

        skeptic: dict[str, Any] = {}
        initial_skeptic: dict[str, Any] = {}
        tiebreaker: dict[str, Any] = {}
        skeptic_counterexample_validation: dict[str, Any] = {}
        union_rescue: dict[str, Any] = {}
        union_skeptic: dict[str, Any] = {}
        if require_skeptic:
            skeptic_prompt = self._SKEPTIC_PROMPT.format(
                requirement=requirement,
                source_section=source_section,
                candidate="\n\n".join(item.prompt_block() for item in selected),
            )
            try:
                skeptic_raw = await asyncio.to_thread(
                    self.llm_client.generate, skeptic_prompt, max_tokens_override=1000, timeout_override=300.0,
                )
                skeptic = self._parse_json(skeptic_raw)
            except Exception as exc:
                skeptic = {"verdict": "none", "proof": f"skeptic judge failed: {exc}"}
            initial_skeptic = skeptic
            if str(skeptic.get("verdict") or "none").lower() != "full":
                # Validate a skeptical counterexample against the selected Go
                # directly. A claimed false positive is not a counterexample
                # to one-way coverage, and an asserted Error/Pass path must
                # match the source before it can reject a full claim.
                validation_prompt = self._COUNTEREXAMPLE_VALIDATION_PROMPT.format(
                    requirement=requirement,
                    source_section=source_section,
                    review=json.dumps(skeptic, ensure_ascii=False),
                    candidates="\n\n".join(item.prompt_block() for item in selected),
                )
                try:
                    validation_raw = await asyncio.to_thread(
                        self.llm_client.generate, validation_prompt,
                        max_tokens_override=1400, timeout_override=300.0,
                    )
                    skeptic_counterexample_validation = self._parse_json(validation_raw)
                except Exception as exc:
                    skeptic_counterexample_validation = {
                        "verdict": "none",
                        "proof": f"skeptical counterexample validation failed: {exc}",
                    }
                validation_names, validation_selected = self._selected_candidates(
                    skeptic_counterexample_validation.get("lint"), candidates
                )
                if str(skeptic_counterexample_validation.get("verdict") or "none").lower() == "full":
                    # This validator receives only the already selected
                    # candidate set. Its optional lint field is explanatory,
                    # so a prose suffix such as \" union\" cannot invalidate
                    # its source-backed full proof.
                    if validation_selected:
                        selected_names, selected = validation_names, validation_selected
                    skeptic = skeptic_counterexample_validation
                # A non-full conclusion without a concrete missed certificate is
                # not a valid refutation of set inclusion. Re-adjudicate it from
                # source rather than silently accepting an inconsistent label.
                if not self._has_counterexample(skeptic):
                    tiebreaker_prompt = self._NONFULL_TIEBREAKER_PROMPT.format(
                        requirement=requirement,
                        source_section=source_section,
                        candidate="\n\n".join(item.prompt_block() for item in selected),
                        reviews=json.dumps({
                            "primary": initial_primary,
                            "counterexample_review": repair,
                            "skeptic": skeptic,
                        }, ensure_ascii=False),
                    )
                    try:
                        tiebreaker_raw = await asyncio.to_thread(
                            self.llm_client.generate, tiebreaker_prompt,
                            max_tokens_override=1200, timeout_override=300.0,
                        )
                        tiebreaker = self._parse_json(tiebreaker_raw)
                    except Exception as exc:
                        tiebreaker = {"verdict": "none", "proof": f"tie-breaker failed: {exc}"}
                    if str(tiebreaker.get("verdict") or "none").lower() == "full":
                        skeptic = tiebreaker
                # A concrete missed certificate may expose an incomplete
                # candidate selection rather than a genuinely uncovered rule.
                # Re-open retrieval over the *same* ranked pool and require a
                # fresh skeptic to confirm any proposed union.  This is a
                # general counterexample-driven search step; it has no rule or
                # lint-specific pairing knowledge.
                if self._has_counterexample(skeptic):
                    rescue_prompt = self._COUNTEREXAMPLE_REVIEW_PROMPT.format(
                        requirement=requirement,
                        source_section=source_section,
                        primary=json.dumps({
                            "initial_primary": initial_primary,
                            "skeptical_counterexample": skeptic,
                        }, ensure_ascii=False),
                        candidates="\n\n".join(item.prompt_block() for item in candidates),
                    )
                    try:
                        rescue_raw = await asyncio.to_thread(
                            self.llm_client.generate, rescue_prompt,
                            max_tokens_override=1400, timeout_override=300.0,
                        )
                        union_rescue = self._parse_json(rescue_raw)
                    except Exception as exc:
                        union_rescue = {
                            "verdict": "none",
                            "proof": f"counterexample-driven union rescue failed: {exc}",
                        }
                    rescue_names, rescue_selected = self._selected_candidates(
                        union_rescue.get("lint"), candidates
                    )
                    if (str(union_rescue.get("verdict") or "none").lower() == "full"
                            and rescue_selected):
                        rescue_skeptic_prompt = self._SKEPTIC_PROMPT.format(
                            requirement=requirement,
                            source_section=source_section,
                            candidate="\n\n".join(item.prompt_block() for item in rescue_selected),
                        )
                        try:
                            rescue_skeptic_raw = await asyncio.to_thread(
                                self.llm_client.generate, rescue_skeptic_prompt,
                                max_tokens_override=1000, timeout_override=300.0,
                            )
                            union_skeptic = self._parse_json(rescue_skeptic_raw)
                        except Exception as exc:
                            union_skeptic = {
                                "verdict": "none",
                                "proof": f"union skeptic failed: {exc}",
                            }
                        if str(union_skeptic.get("verdict") or "none").lower() == "full":
                            primary = union_rescue
                            selected_names, selected = rescue_names, rescue_selected
                            skeptic = union_skeptic
                if str(skeptic.get("verdict") or "none").lower() != "full":
                    return {
                        "has_coverage": False, "verdict": "partial",
                        "lint_name": None,
                        "reasoning": "Primary judge claimed full, but the independent skeptical review did not confirm set inclusion: "
                                     + str(skeptic.get("proof") or skeptic.get("counterexample") or "")[:1800],
                        "fields": {}, "n_candidates": len(candidates), "match_method": "native_go_two_pass",
                        "audit": {"primary": initial_primary, "counterexample_review": repair,
                                  "counterexample_validation": counterexample_validation,
                                  "skeptic": initial_skeptic, "tie_breaker": tiebreaker,
                                  "skeptic_counterexample_validation": skeptic_counterexample_validation,
                                  "union_rescue": union_rescue, "union_skeptic": union_skeptic,
                                  "confirmation": skeptic,
                                  "selected": [item.name for item in selected],
                                  "candidate_names": [item.name for item in candidates]},
                    }

        return {
            "has_coverage": True, "verdict": "full", "lint_name": "+".join(selected_names),
            "reasoning": str(skeptic.get("proof") or primary.get("proof") or "")[:2000],
            "fields": {}, "n_candidates": len(candidates), "match_method": "native_go_two_pass",
            "audit": {
                "primary": initial_primary,
                "counterexample_review": repair,
                "counterexample_validation": counterexample_validation,
                "skeptic": initial_skeptic,
                "tie_breaker": tiebreaker,
                "skeptic_counterexample_validation": skeptic_counterexample_validation,
                "union_rescue": union_rescue,
                "union_skeptic": union_skeptic,
                "confirmation": skeptic,
                "selected": [item.name for item in selected],
                "native_files": [str(item.path) for item in selected],
                "native_sha256": {item.name: item.code_sha256 for item in selected},
                "candidate_names": [item.name for item in candidates],
            },
        }
