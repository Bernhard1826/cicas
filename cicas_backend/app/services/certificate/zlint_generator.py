"""
Compatibility wrapper for zlint code generation.

The old implementation generated Go through L-subclass prompt templates. The
active generator now goes through the atomic DSL/template pipeline under
app.services.certificate.codegen. This module keeps the historical
ZlintCodeGenerator API stable for routes and services that still import it.
"""
from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from app.services.certificate.codegen import det_codegen, intree_emitter


@dataclass
class CodeGenResult:
    """Result of a single code generation attempt."""

    rule_id: str
    lint_name: str
    lint_subclass: str
    success: bool
    go_code: Optional[str] = None
    test_code: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None
    llm_params: Optional[Dict[str, Any]] = None
    error: str = ""
    attempts: int = 1
    generation_time_ms: float = 0
    description_from_ir: str = ""
    status: str = ""
    ir_json: Optional[Dict[str, Any]] = None


@dataclass
class BatchCodeGenResult:
    """Result of batch code generation."""

    total: int = 0
    success: int = 0
    failed: int = 0
    skipped: int = 0
    results: List[CodeGenResult] = field(default_factory=list)
    total_time_s: float = 0


class ZlintCodeGenerator:
    """Generate zlint Go code through the atomic DSL/template pipeline.

    The constructor accepts the old LLM-template parameters for call-site
    compatibility. They are intentionally not used by the deterministic atomic
    path; the cascade itself controls whether an LLM tree-synthesis fallback is
    allowed.
    """

    def __init__(
        self,
        api_key: str = "",
        api_base: str = "",
        model: str = "",
        zlint_lints_dir: Optional[Path] = None,
        max_retries: int = 3,
        rate_limit_rpm: int = 100,
        allow_llm: bool = True,
    ):
        self.api_key = api_key
        self.api_base = api_base
        self.model = model
        self.zlint_lints_dir = zlint_lints_dir
        self.max_retries = max_retries
        self.rate_limit_rpm = rate_limit_rpm
        self.allow_llm = allow_llm

    def generate(self, ir: Dict[str, Any]) -> CodeGenResult:
        """Generate a full in-tree zlint Go file from an IR dict."""
        t0 = time.time()
        ir = dict(ir or {})
        rid = _extract_rule_id(ir)
        rule_id = str(rid or ir.get("rule_id") or ir.get("_db_rule_id") or "unknown")
        lint_subclass = str(ir.get("lint_subclass") or "atomic_template")
        metadata = self.ir_to_metadata(ir)

        lintable, reason = _lintability(ir)
        if not lintable:
            return CodeGenResult(
                rule_id=rule_id,
                lint_name="",
                lint_subclass=lint_subclass,
                success=False,
                metadata=metadata,
                error=reason or "Rule is not lintable",
                generation_time_ms=(time.time() - t0) * 1000,
                description_from_ir=metadata.get("description", ""),
                status="skipped",
                ir_json=ir,
            )

        rule = _rule_from_ir(ir, rid)
        try:
            generated = _generate_tree(rule, allow_llm=self.allow_llm)
        except Exception as e:
            return CodeGenResult(
                rule_id=rule_id,
                lint_name="",
                lint_subclass=lint_subclass,
                success=False,
                metadata=metadata,
                error=f"atomic template generation failed: {e}",
                generation_time_ms=(time.time() - t0) * 1000,
                description_from_ir=metadata.get("description", ""),
                status="failed",
                ir_json=ir,
            )

        tree = generated.get("tree")
        precondition = generated.get("precondition")
        method = generated.get("method") or ""
        if tree is None:
            return CodeGenResult(
                rule_id=rule_id,
                lint_name="",
                lint_subclass=lint_subclass,
                success=False,
                metadata={**metadata, "generation_method": "atomic_template"},
                llm_params=_generation_trace(generated),
                error=generated.get("reason") or "atomic template generation returned no tree",
                generation_time_ms=(time.time() - t0) * 1000,
                description_from_ir=metadata.get("description", ""),
                status="failed",
                ir_json=ir,
            )

        try:
            severity = det_codegen.severity_from_obligation(
                rule.get("obligation") or ir.get("obligation")
            )
            rendered = intree_emitter.render_intree_file(
                rid,
                rule.get("source") or "",
                str(rule.get("section") or ""),
                rule.get("text") or "",
                tree,
                precondition=precondition,
                severity=severity,
                title=rule.get("title") or "",
                ir=ir,
            )
        except Exception as e:
            return CodeGenResult(
                rule_id=rule_id,
                lint_name="",
                lint_subclass=lint_subclass,
                success=False,
                metadata={**metadata, "generation_method": "atomic_template"},
                llm_params=_generation_trace(generated),
                error=f"atomic template render failed: {e}",
                generation_time_ms=(time.time() - t0) * 1000,
                description_from_ir=metadata.get("description", ""),
                status="failed",
                ir_json=ir,
            )

        metadata = {
            **metadata,
            "lint_name": rendered["lint_name"],
            "package": rendered["pkg"],
            "struct_name": rendered["struct_name"],
            "filename": rendered["filename"],
            "source": rule.get("source") or metadata.get("source", ""),
            "section": str(rule.get("section") or metadata.get("section", "")),
            "severity": severity,
            "generation_method": "atomic_template",
            "codegen_method": method or "unknown",
        }
        return CodeGenResult(
            rule_id=rule_id,
            lint_name=rendered["lint_name"],
            lint_subclass=lint_subclass,
            success=True,
            go_code=rendered["file_content"],
            test_code=self._generate_test_code(rendered["pkg"], rendered["struct_name"]),
            metadata=metadata,
            llm_params=_generation_trace(generated),
            generation_time_ms=(time.time() - t0) * 1000,
            description_from_ir=metadata.get("description", ""),
            status="llm_success" if method == "llm" else "success",
            ir_json=ir,
        )

    def generate_batch(
        self,
        rules: List[Dict[str, Any]],
        output_dir: Optional[Path] = None,
        progress_callback=None,
    ) -> BatchCodeGenResult:
        """Generate code for a batch of IR dicts."""
        t0 = time.time()
        batch_result = BatchCodeGenResult(total=len(rules))

        for i, ir in enumerate(rules):
            result = self.generate(ir)
            batch_result.results.append(result)

            if result.success:
                batch_result.success += 1
                if output_dir:
                    self._save_generated_lint(result, output_dir)
            elif result.status == "skipped":
                batch_result.skipped += 1
            else:
                batch_result.failed += 1

            if progress_callback:
                progress_callback(i + 1, len(rules), result)

        batch_result.total_time_s = time.time() - t0
        return batch_result

    def generate_from_ir(self, ir: Dict[str, Any]) -> Dict[str, Any]:
        """Compatibility: return the old dict-shaped generation response."""
        return self._codegen_result_to_dict(self.generate(ir))

    def generate_from_ir_dict(self, ir: Dict[str, Any]) -> Tuple[str, str, str, Dict[str, Any]]:
        """Compatibility with old tuple-returning call sites."""
        result = self.generate(ir)
        return (
            result.go_code or "",
            result.test_code or "",
            json.dumps(result.ir_json or ir or {}, ensure_ascii=False),
            result.metadata or {},
        )

    @staticmethod
    def ir_to_metadata(ir: Dict[str, Any]) -> Dict[str, Any]:
        """Extract deterministic metadata from IR/rule context."""
        ir = ir or {}
        source = _extract_source(ir)
        section = _extract_section(ir)
        text = _extract_rule_text(ir)
        rid = _extract_rule_id(ir)
        lint_name = f"cicasgen_{rid}" if rid else "cicasgen_unknown"
        try:
            package, source_const = intree_emitter.resolve_package(source)
        except Exception:
            package, source_const = "", source
        return {
            "lint_name": lint_name,
            "struct_name": f"CicasGen{rid}" if rid else "CicasGenUnknown",
            "description": text,
            "citation": f"{source}: {section}" if section else source,
            "source": source_const,
            "source_id": source,
            "section": section,
            "package": package,
            "generation_method": "atomic_template",
        }

    @staticmethod
    def _generate_test_code(pkg: str, struct_name: str) -> str:
        """Generate a minimal constructor smoke test for the emitted lint."""
        return f'''package {pkg}

import "testing"

func TestNew{struct_name}(t *testing.T) {{
\tl := New{struct_name}()
\tif l == nil {{
\t\tt.Fatalf("expected non-nil lint")
\t}}
}}
'''

    def _codegen_result_to_dict(self, result: CodeGenResult) -> Dict[str, Any]:
        if result.success:
            return {
                "success": True,
                "go_code": result.go_code or "",
                "test_code": result.test_code or "",
                "lint_name": result.lint_name or "unknown",
                "metadata": result.metadata or {},
                "ir_json": result.ir_json or {},
            }
        return {
            "success": False,
            "go_code": "",
            "test_code": "",
            "lint_name": result.lint_name or "unknown",
            "metadata": result.metadata or {},
            "ir_json": result.ir_json or {},
            "error": result.error or "",
        }

    @staticmethod
    def _save_generated_lint(result: CodeGenResult, output_dir: Path):
        """Save generated lint and smoke test under output_dir/<package>/."""
        pkg = result.metadata.get("package", "rfc") if result.metadata else "rfc"
        pkg_dir = output_dir / pkg
        pkg_dir.mkdir(parents=True, exist_ok=True)

        lint_name = result.lint_name or "unknown"
        (pkg_dir / f"lint_{lint_name}.go").write_text(
            result.go_code or "", encoding="utf-8"
        )
        if result.test_code:
            (pkg_dir / f"lint_{lint_name}_test.go").write_text(
                result.test_code, encoding="utf-8"
            )


def _generation_trace(generated: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "method": generated.get("method"),
        "reason": generated.get("reason", ""),
        "llm_raw": generated.get("llm_raw", ""),
    }


def _generate_tree(rule: Dict[str, Any], allow_llm: bool = True) -> Dict[str, Any]:
    """Generate a DSL tree without importing the LLM fallback at module load."""
    rid = int(rule.get("id") or 0)
    ir = rule.get("ir") or {}
    obligation = (
        rule.get("obligation")
        or (ir.get("obligation") if isinstance(ir, dict) else "")
        or ""
    )
    if str(obligation).strip().upper().replace("_", " ") in {"MAY", "OPTIONAL"}:
        return {
            "tree": None,
            "precondition": None,
            "method": None,
            "reason": "non_code_obligation: MAY/OPTIONAL is permissive and has no violation lint",
            "llm_raw": "",
        }

    try:
        det_ir = dict(ir)
        det_ir.setdefault("_rule_title", rule.get("title") or "")
        det_ir.setdefault("_rule_text", rule.get("text") or "")
        det_ir.setdefault("_rule_source", rule.get("source") or "")
        tree = det_codegen.deterministic_tree(
            rid, det_ir, section=rule.get("section")
        )
    except Exception:
        tree = None
    if tree is not None:
        return {
            "tree": tree,
            "precondition": None,
            "method": "deterministic",
            "reason": "",
            "llm_raw": "",
        }
    if not allow_llm:
        return {
            "tree": None,
            "precondition": None,
            "method": None,
            "reason": "deterministic_only",
            "llm_raw": "",
        }

    try:
        from app.services.certificate.codegen import cascade
    except Exception as e:
        return {
            "tree": None,
            "precondition": None,
            "method": None,
            "reason": f"llm_fallback_unavailable: {e}",
            "llm_raw": "",
        }
    return cascade.generate_tree(rule, allow_llm=True)


def _lintability(ir: Dict[str, Any]) -> Tuple[bool, str]:
    lintability = ir.get("zlint_lintability")
    if isinstance(lintability, dict) and lintability.get("can_generate") is False:
        return False, str(lintability.get("reason") or "Rule cannot generate zlint code")
    if "lintable" in ir and ir.get("lintable") is False:
        return False, str(ir.get("non_lintable_reason") or "Rule is not lintable")
    return True, ""


def _rule_from_ir(ir: Dict[str, Any], rid: int) -> Dict[str, Any]:
    return {
        "id": rid,
        "text": _extract_rule_text(ir),
        "source": _extract_source(ir),
        "section": _extract_section(ir),
        "title": str(ir.get("_rule_title") or ir.get("title") or ""),
        "obligation": str(ir.get("_rule_obligation") or ir.get("obligation") or ""),
        "requirement_level": str(ir.get("_rule_obligation") or ir.get("obligation") or ""),
        "ir": ir,
    }


def _extract_rule_id(ir: Dict[str, Any]) -> int:
    for key in ("_db_rule_id", "id", "rule_db_id", "rule_id"):
        value = ir.get(key)
        if isinstance(value, int):
            return value
        if isinstance(value, str):
            s = value.strip()
            if s.isdigit():
                return int(s)
            m = re.fullmatch(r"[Rr](\d+)", s)
            if m:
                return int(m.group(1))
    return 0


def _extract_rule_text(ir: Dict[str, Any]) -> str:
    for key in ("_rule_text", "rule_text", "description", "text"):
        value = ir.get(key)
        if value:
            return str(value)
    constraint = ir.get("constraint")
    if isinstance(constraint, dict) and constraint.get("raw_text"):
        return str(constraint["raw_text"])
    return ""


def _extract_section(ir: Dict[str, Any]) -> str:
    for key in ("_rule_section", "section"):
        value = ir.get(key)
        if value:
            return str(value)
    prov = ir.get("provenance")
    if isinstance(prov, list) and prov:
        section = prov[0].get("section") if isinstance(prov[0], dict) else None
        if section:
            return str(section)
    return ""


def _extract_source(ir: Dict[str, Any]) -> str:
    for key in ("_rule_source", "source", "spec_family"):
        value = ir.get(key)
        if value:
            return _normalize_source(str(value))
    prov = ir.get("provenance")
    if isinstance(prov, list) and prov:
        source = prov[0].get("source_id") if isinstance(prov[0], dict) else None
        if source:
            return _normalize_source(str(source))
    return "RFC5280"


def _normalize_source(source: str) -> str:
    s = (source or "").strip()
    key = s.upper().replace(" ", "").replace("_", "-")
    if "CABF" in key or key in {"BR", "CABF-TLS-BR", "CABF-SERVER"}:
        return "CABF-BR"
    if "RFC" in key or "5280" in key:
        return "RFC5280"
    return s
