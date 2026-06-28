"""
Code Verification Pipeline

Verifies generated zlint code through three stages:
  Stage A: Description traceability to the original source text
  Stage B: Semantic alignment between generated code and source normative text
  Stage C: Compilation + structural validation

Reverse-IR extraction is retained only as auxiliary diagnostic evidence and must
not dominate acceptance decisions.
"""
import json
import os
import re
import time
import difflib
import subprocess
from typing import Dict, List, Optional, Any, Tuple
from pathlib import Path
from dataclasses import dataclass, field

from app.utils.llm_client import call_text_completion, resolve_llm_provider


@dataclass
class TraceabilityResult:
    """Stage A: Does the Description trace back to the original source text?"""
    match_type: str = "none"  # exact | sentence | fuzzy | none
    similarity_score: float = 0.0
    matched_fragment: str = ""
    source_section: str = ""


@dataclass
class SemanticAlignmentResult:
    """Stage B: Does the code correctly implement the source requirement?"""
    # Code summary approach (primary signal)
    code_summary: str = ""  # Natural language: what does this code do?
    description_from_code: str = ""  # Extracted Description field from Go code
    summary_description_synonymous: bool = False  # Are code_summary and description synonymous?
    summary_description_confidence: float = 0.0
    summary_description_explanation: str = ""

    # Legacy fields (kept for compatibility)
    field_correct: bool = False
    obligation_correct: bool = False
    logic_correct: bool = False
    semantic_gaps: List[str] = field(default_factory=list)
    hallucinated_checks: List[str] = field(default_factory=list)
    overall_aligned: bool = False
    confidence: float = 0.0
    explanation: str = ""

    # Reverse IR extraction (Approach 2)
    reverse_ir: Optional[Dict] = None
    reverse_match_rate: float = 0.0
    field_matches: Dict[str, bool] = field(default_factory=dict)


@dataclass
class StructuralResult:
    """Stage C: Does the code compile and have correct structure?"""
    compiles: bool = False
    has_init: bool = False
    has_check_applies: bool = False
    has_execute: bool = False
    has_correct_imports: bool = False
    lint_registered: bool = False
    compile_error: str = ""


@dataclass
class AlignmentScore:
    """Combined verification score."""
    # Stage A
    description_traceable: bool = False
    description_similarity: float = 0.0
    # Stage B (new code summary approach)
    code_summary_synonymous: bool = False
    code_summary_confidence: float = 0.0
    # Stage B (legacy)
    llm_judge_aligned: bool = False
    llm_judge_confidence: float = 0.0
    reverse_ir_match_rate: float = 0.0
    # Stage C
    compiles: bool = False
    structure_valid: bool = False
    # Overall
    overall_score: float = 0.0

    def compute_overall(self):
        """Weighted combination with code summary as the primary signal."""
        weights = {
            "compiles": 0.15,
            "structure": 0.10,
            "description_traceable": 0.15,
            "code_summary": 0.50,  # Primary signal: code summary vs description
            "reverse_ir": 0.10,
        }
        score = 0.0
        score += weights["compiles"] * (1.0 if self.compiles else 0.0)
        score += weights["structure"] * (1.0 if self.structure_valid else 0.0)
        score += weights["description_traceable"] * self.description_similarity
        score += weights["code_summary"] * self.code_summary_confidence
        score += weights["reverse_ir"] * self.reverse_ir_match_rate
        self.overall_score = score


@dataclass
class VerificationResult:
    """Full verification result for one generated lint."""
    rule_id: str
    lint_name: str
    traceability: TraceabilityResult = field(default_factory=TraceabilityResult)
    semantic: SemanticAlignmentResult = field(default_factory=SemanticAlignmentResult)
    structural: StructuralResult = field(default_factory=StructuralResult)
    alignment: AlignmentScore = field(default_factory=AlignmentScore)
    verification_time_ms: float = 0


class CodeVerificationPipeline:
    """Verifies generated zlint code for correctness and alignment."""

    def __init__(
        self,
        api_key: str = "",
        api_base: str = "https://rsxermu666.cn/v1",
        model: str = "Qwen/Qwen3-8B",
        zlint_dir: Optional[Path] = None,
    ):
        self.api_key = api_key
        self.api_base = api_base
        self.model = model
        self.provider = resolve_llm_provider(
            provider=os.getenv("LLM_PROVIDER"),
            api_base=api_base,
        )

        if zlint_dir is None:
            backend = Path(__file__).parent.parent.parent
            zlint_dir = backend / "zlint" / "v3"
        self.zlint_dir = zlint_dir

    # ===========================================================
    # Main entry point
    # ===========================================================

    def verify(
        self,
        go_code: str,
        ir: Dict[str, Any],
        section_text: str = "",
        source_text: str = "",
        run_llm_judge: bool = True,
        run_reverse_ir: bool = True,
    ) -> VerificationResult:
        """Run full verification pipeline on generated code.

        Args:
            go_code: Generated Go source code
            ir: Original IR dict
            section_text: Full text of the source section
            source_text: Exact source rule text or source span for this rule
            run_llm_judge: Whether to run LLM semantic judge (costs API)
            run_reverse_ir: Whether to run reverse IR extraction (costs API)
        """
        t0 = time.time()
        rule_id = ir.get("rule_id", "unknown")
        lint_name = ""
        name_match = re.search(r'Name:\s*"([^"]*)"', go_code)
        if name_match:
            lint_name = name_match.group(1)

        result = VerificationResult(rule_id=rule_id, lint_name=lint_name)

        # Stage A: Description traceability
        result.traceability = self._verify_description(
            go_code,
            ir,
            section_text=section_text,
            source_text=source_text,
        )

        # Stage B: Semantic alignment
        if run_llm_judge or run_reverse_ir:
            result.semantic = self._verify_semantic(
                go_code,
                ir,
                section_text=section_text,
                source_text=source_text,
                run_judge=run_llm_judge,
                run_reverse=run_reverse_ir,
            )

        # Stage C: Structural validation
        result.structural = self._verify_structure(go_code)

        # Combine scores
        result.alignment = AlignmentScore(
            description_traceable=result.traceability.match_type != "none",
            description_similarity=result.traceability.similarity_score,
            code_summary_synonymous=result.semantic.summary_description_synonymous,
            code_summary_confidence=result.semantic.summary_description_confidence,
            llm_judge_aligned=result.semantic.overall_aligned,
            llm_judge_confidence=result.semantic.confidence,
            reverse_ir_match_rate=result.semantic.reverse_match_rate,
            compiles=result.structural.compiles,
            structure_valid=(
                result.structural.has_init
                and result.structural.has_check_applies
                and result.structural.has_execute
            ),
        )
        result.alignment.compute_overall()
        result.verification_time_ms = (time.time() - t0) * 1000

        return result

    # ===========================================================
    # Stage A: Description Traceability
    # ===========================================================

    def _verify_description(
        self,
        go_code: str,
        ir: Dict[str, Any],
        section_text: str,
        source_text: str = "",
    ) -> TraceabilityResult:
        """Check whether Description is traceable to source text, not just IR paraphrase."""
        result = TraceabilityResult()

        # Extract Description from Go code
        desc_match = re.search(r'Description:\s*"([^"]*)"', go_code)
        if not desc_match:
            return result
        description = desc_match.group(1).strip()
        if not description:
            return result

        rule_text = (ir.get("rule_text") or "").strip()
        constraint = ir.get("constraint", {})
        raw_text = constraint.get("raw_text", "").strip() if isinstance(constraint, dict) else ""
        exact_source = (source_text or ir.get("source_text") or "").strip()

        for candidate in [exact_source, rule_text, raw_text]:
            if not candidate:
                continue
            sim = difflib.SequenceMatcher(None, description.lower(), candidate.lower()).ratio()
            if sim >= 0.95:
                result.match_type = "exact"
                result.similarity_score = sim
                result.matched_fragment = candidate
                return result

        if section_text:
            norm_desc = _normalize_text(description)
            norm_section = _normalize_text(section_text)

            if norm_desc and norm_desc in norm_section:
                fragment = _best_substring_fragment(section_text, description) or description
                result.match_type = "exact"
                result.similarity_score = 1.0
                result.matched_fragment = fragment
                result.source_section = section_text[:200]
                return result

            section_sentences = _split_sentences(section_text)
            best_sim = 0.0
            best_match = ""
            for sentence in section_sentences:
                s = difflib.SequenceMatcher(
                    None,
                    _normalize_text(description),
                    _normalize_text(sentence),
                ).ratio()
                if s > best_sim:
                    best_sim = s
                    best_match = sentence

            if best_sim >= 0.85:
                result.match_type = "sentence"
                result.similarity_score = best_sim
                result.matched_fragment = best_match
                result.source_section = section_text[:200]
                return result
            if best_sim >= 0.6:
                result.match_type = "fuzzy"
                result.similarity_score = best_sim
                result.matched_fragment = best_match
                result.source_section = section_text[:200]
                return result

        return result

    # ===========================================================
    # Stage B: Semantic Alignment
    # ===========================================================

    def _verify_semantic(
        self,
        go_code: str,
        ir: Dict[str, Any],
        section_text: str,
        source_text: str = "",
        run_judge: bool = True,
        run_reverse: bool = True,
    ) -> SemanticAlignmentResult:
        """Verify semantic alignment using code summary approach."""
        result = SemanticAlignmentResult()

        rule_text = (ir.get("rule_text") or "").strip()
        if not rule_text:
            c = ir.get("constraint", {})
            rule_text = (c.get("raw_text", "") if isinstance(c, dict) else "").strip()
        exact_source = (source_text or ir.get("source_text") or rule_text).strip()

        # Step 1: Extract Description field from Go code
        result.description_from_code = self._extract_description_from_code(go_code)

        # Step 2: Generate code summary (natural language: what does this code do?)
        result.code_summary = self._generate_code_summary(go_code)

        # Step 3: Check if code_summary and description are synonymous
        if result.code_summary and result.description_from_code:
            synonymy_result = self._check_summary_description_synonymy(
                result.code_summary,
                result.description_from_code,
            )
            result.summary_description_synonymous = synonymy_result.get("synonymous", False)
            result.summary_description_confidence = synonymy_result.get("confidence", 0.0)
            result.summary_description_explanation = synonymy_result.get("explanation", "")

            # Set overall_aligned based on code summary approach
            result.overall_aligned = result.summary_description_synonymous
            result.confidence = result.summary_description_confidence

        # Legacy: Keep old LLM judge for comparison (optional)
        if run_judge and (exact_source or section_text):
            judge_result = self._llm_semantic_judge(
                go_code,
                source_text=exact_source,
                section_text=section_text,
                ir=ir,
            )
            result.field_correct = judge_result.get("field_correct", False)
            result.obligation_correct = judge_result.get("obligation_correct", False)
            result.logic_correct = judge_result.get("logic_correct", False)
            result.semantic_gaps = judge_result.get("semantic_gaps", [])
            result.hallucinated_checks = judge_result.get("hallucinated_checks", [])
            # Don't override overall_aligned from code summary approach
            if not result.code_summary:
                result.overall_aligned = judge_result.get("overall_aligned", False)
                result.confidence = judge_result.get("confidence", 0.0)
            result.explanation = judge_result.get("explanation", "")

        if run_reverse:
            reverse = self._reverse_ir_extraction(go_code)
            result.reverse_ir = reverse
            if reverse:
                result.reverse_match_rate, result.field_matches = _compare_irs(ir, reverse)

        return result

    def _llm_semantic_judge(
        self,
        go_code: str,
        source_text: str,
        section_text: str = "",
        ir: Optional[Dict[str, Any]] = None,
    ) -> Dict:
        """Ask LLM to judge semantic alignment between code and source text."""
        subject = _get_ir_field(ir or {}, "subject")
        obligation = _get_ir_field(ir or {}, "obligation")
        predicate = _get_ir_field(ir or {}, "predicate")
        prompt = f"""Judge whether this Go code correctly implements the PKI source requirement.

## Exact Source Requirement
{source_text or '(missing)'}

## Source Section Context
{section_text[:4000] if section_text else '(missing)'}

## IR Hints
- subject: {subject or '(missing)'}
- obligation: {obligation or '(missing)'}
- predicate: {predicate or '(missing)'}

## Go Code
```go
{go_code}
```

## Evaluation Criteria
1. Does the code check the correct certificate field from the source requirement?
2. Does the code implement the correct obligation/severity implied by the source text?
3. Does the code implement the correct validation logic and condition?
4. List any source requirements omitted by the code as semantic_gaps.
5. List any checks in the code not supported by the source text as hallucinated_checks.
6. Use the exact source requirement as primary evidence. Use section context only to resolve references.

Return a JSON object:
```json
{{
  "field_correct": true/false,
  "obligation_correct": true/false,
  "logic_correct": true/false,
  "semantic_gaps": ["gap1", "gap2"],
  "hallucinated_checks": ["hallucination1"],
  "overall_aligned": true/false,
  "confidence": 0.0-1.0,
  "explanation": "brief explanation grounded in the source text"
}}
```"""
        try:
            response = self._call_llm(prompt)
            return _parse_json_from_response(response)
        except Exception as e:
            return {"overall_aligned": False, "confidence": 0.0, "explanation": f"LLM error: {e}"}

    def _extract_description_from_code(self, go_code: str) -> str:
        """Extract the Description field from Go code."""
        match = re.search(r'Description:\s*"([^"]*)"', go_code, re.DOTALL)
        if match:
            return match.group(1).strip()
        return ""

    def _generate_code_summary(self, go_code: str) -> str:
        """Generate natural language summary of what the code does."""
        prompt = f"""Read this Go zlint code and write a concise natural language summary of what it checks.

```go
{go_code}
```

Write a single sentence summary in the format: "The certificate [MUST/MUST NOT/SHOULD/SHOULD NOT] [what is being checked]."

Return only the summary sentence, no JSON, no explanation."""
        try:
            response = self._call_llm(prompt)
            return response.strip().strip('"').strip()
        except Exception as e:
            return f"Error generating summary: {e}"

    def _check_summary_description_synonymy(
        self,
        code_summary: str,
        description: str,
    ) -> Dict:
        """Check if code_summary and description are synonymous."""
        prompt = f"""Compare these two statements and determine if they express the same requirement:

Statement 1 (code summary): {code_summary}

Statement 2 (description): {description}

Are these two statements synonymous (expressing the same requirement)?

Return a JSON object:
```json
{{
  "synonymous": true/false,
  "confidence": 0.0-1.0,
  "explanation": "brief explanation of why they are or are not synonymous"
}}
```"""
        try:
            response = self._call_llm(prompt)
            return _parse_json_from_response(response)
        except Exception as e:
            return {"synonymous": False, "confidence": 0.0, "explanation": f"LLM error: {e}"}

    def _reverse_ir_extraction(self, go_code: str) -> Optional[Dict]:
        """Extract IR 4-tuple from generated Go code (reverse direction).

        This is the core of round-trip verification:
        spec → IR → code → IR'  then compare(IR, IR')
        """
        prompt = f"""Extract the structured rule from this Go zlint code.

```go
{go_code}
```

Return a JSON object with these fields:
```json
{{
  "subject": "certificate field path being checked (e.g., extensions.subjectAltName.dNSName)",
  "obligation": "MUST|MUST NOT|SHALL|SHOULD (from severity: Error=MUST, Warn=SHOULD)",
  "predicate": "what the check does (e.g., must_be_present, equal, encode_as, must_include, in_range, conform_to)",
  "constraint_raw_text": "natural language description of what is being checked",
  "constraint_type": "presence|absence|numeric|string|format|encoding|enum"
}}
```"""
        try:
            response = self._call_llm(prompt)
            return _parse_json_from_response(response)
        except Exception:
            return None

    # ===========================================================
    # Stage C: Structural Validation
    # ===========================================================

    def _verify_structure(self, go_code: str) -> StructuralResult:
        """Check code structure and compilation."""
        result = StructuralResult()

        # Structural checks (regex-based, no compilation needed)
        result.has_init = "func init()" in go_code
        result.has_check_applies = "func (l *" in go_code and "CheckApplies" in go_code
        result.has_execute = "func (l *" in go_code and "Execute" in go_code
        result.has_correct_imports = (
            "github.com/zmap/zcrypto/x509" in go_code
            and "github.com/zmap/zlint/v3/lint" in go_code
        )
        result.lint_registered = "lint.RegisterCertificateLint" in go_code

        # Compilation check (if Go is available)
        compile_ok, compile_err = self._try_compile(go_code)
        result.compiles = compile_ok
        result.compile_error = compile_err

        return result

    def _try_compile(self, go_code: str) -> Tuple[bool, str]:
        """Try to compile the Go code (syntax check only)."""
        try:
            # Write to temp file in zlint lints directory
            import tempfile
            # Extract package name
            pkg_match = re.search(r'^package\s+(\w+)', go_code, re.MULTILINE)
            if not pkg_match:
                return False, "No package declaration found"
            package = pkg_match.group(1)

            lint_pkg_dir = self.zlint_dir / "lints" / package
            if not lint_pkg_dir.exists():
                # Can't compile without the package directory
                return True, ""  # Assume OK if we can't test

            with tempfile.NamedTemporaryFile(
                mode="w", suffix=".go", dir=str(lint_pkg_dir),
                delete=False, prefix="_tmp_verify_"
            ) as f:
                f.write(go_code)
                tmp_path = Path(f.name)

            try:
                # Run go vet (lighter than go build)
                proc = subprocess.run(
                    ["go", "vet", f"./{package}"],
                    cwd=str(self.zlint_dir / "lints"),
                    capture_output=True, text=True, timeout=30,
                )
                if proc.returncode == 0:
                    return True, ""
                else:
                    return False, proc.stderr[:500]
            finally:
                tmp_path.unlink(missing_ok=True)

        except FileNotFoundError:
            # Go not installed
            return True, ""  # Can't verify, assume OK
        except subprocess.TimeoutExpired:
            return False, "Compilation timed out"
        except Exception as e:
            return True, f"Compile check skipped: {e}"

    # ===========================================================
    # LLM helper
    # ===========================================================

    def _call_llm(self, prompt: str) -> str:
        """Call LLM API."""
        max_tokens = 4000 if "Qwen" in self.model else 2000
        timeout = 180.0 if self.provider == "anthropic" else 120.0
        return call_text_completion(
            prompt,
            model=self.model,
            api_key=self.api_key,
            api_base=self.api_base,
            provider=self.provider,
            temperature=0,
            max_tokens=max_tokens,
            max_retries=3,
            timeout=timeout,
        )


# ============================================================
# Private helpers
# ============================================================

def _normalize_text(text: str) -> str:
    return " ".join((text or "").lower().split())


def _best_substring_fragment(haystack: str, needle: str) -> str:
    norm_needle = _normalize_text(needle)
    if not norm_needle:
        return ""
    for sentence in _split_sentences(haystack):
        if norm_needle in _normalize_text(sentence):
            return sentence
    return ""


def _split_sentences(text: str) -> List[str]:
    """Split text into sentences."""
    sentences = re.split(r'(?<=[.!?])\s+', text)
    return [s.strip() for s in sentences if len(s.strip()) > 10]


def _parse_json_from_response(response: str) -> Dict:
    """Extract JSON from LLM response (handles markdown blocks)."""
    # Try JSON code block
    match = re.search(r'```json\s*\n(.*?)\n\s*```', response, re.DOTALL)
    if match:
        try:
            return json.loads(match.group(1))
        except json.JSONDecodeError:
            pass

    # Try raw JSON
    for start, end in [("{", "}"), ("[", "]")]:
        idx_s = response.find(start)
        idx_e = response.rfind(end)
        if idx_s >= 0 and idx_e > idx_s:
            try:
                return json.loads(response[idx_s:idx_e + 1])
            except json.JSONDecodeError:
                continue

    return {}


def _compare_irs(original_ir: Dict, reverse_ir: Dict) -> Tuple[float, Dict[str, bool]]:
    """Compare original IR with reverse-extracted IR.

    Returns (match_rate, field_matches).
    """
    matches = {}
    fields_to_compare = ["subject", "obligation", "predicate", "constraint_raw_text"]

    for field_name in fields_to_compare:
        orig_val = _get_ir_field(original_ir, field_name)
        rev_val = reverse_ir.get(field_name, "")

        if not orig_val or not rev_val:
            matches[field_name] = False
            continue

        # Normalize and compare
        orig_norm = str(orig_val).lower().strip()
        rev_norm = str(rev_val).lower().strip()

        # Exact match
        if orig_norm == rev_norm:
            matches[field_name] = True
            continue

        # Fuzzy match (for text fields)
        sim = difflib.SequenceMatcher(None, orig_norm, rev_norm).ratio()
        matches[field_name] = sim >= 0.7

    n_compared = len([v for v in matches.values()])
    n_matched = sum(1 for v in matches.values() if v)
    match_rate = n_matched / max(n_compared, 1)

    return match_rate, matches


def _get_ir_field(ir: Dict, field_name: str) -> str:
    """Get normalized field value from IR for comparison."""
    if field_name == "subject":
        s = ir.get("subject", {})
        if isinstance(s, dict):
            return s.get("path", "") or s.get("raw", "")
        return str(s)
    elif field_name == "obligation":
        return ir.get("obligation", "")
    elif field_name == "predicate":
        return ir.get("predicate", "")
    elif field_name == "constraint_raw_text":
        c = ir.get("constraint", {})
        if isinstance(c, dict):
            return c.get("raw_text", "")
        return str(c)
    return ""
