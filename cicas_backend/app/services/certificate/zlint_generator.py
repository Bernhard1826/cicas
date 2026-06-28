"""
LLM-based zlint Code Generator

Generates zlint Go code from structured IR using L-subclass templates.
Uses LLM to fill template parameters, then assembles complete Go code.

Pipeline: IR → metadata → template selection → LLM parameter fill → assemble → postprocess
"""
import json
import os
import re
import time
import random
from typing import Dict, List, Optional, Any, Tuple
from pathlib import Path
from dataclasses import dataclass, field

import httpx

from app.utils.llm_client import call_text_completion, resolve_llm_provider

from app.services.certificate.l_subclass_templates import (
    LSubclassTemplateLibrary,
)
from app.services.certificate.llm_codegen_prompt import (
    build_codegen_prompt,
    parse_codegen_response,
    select_few_shot_examples,
    postprocess_go_code,
)


@dataclass
class CodeGenResult:
    """Result of a single code generation attempt."""
    rule_id: str
    lint_name: str
    lint_subclass: str
    success: bool
    go_code: Optional[str] = None
    test_code: Optional[str] = None
    metadata: Optional[Dict[str, str]] = None
    llm_params: Optional[Dict] = None
    error: str = ""
    attempts: int = 1
    generation_time_ms: float = 0
    description_from_ir: str = ""  # Original rule_text used as Description


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
    """Generates zlint Go code from IR using LLM + L-subclass templates + IR field guard.

    全量 LLM 路径：所有代码生成均通过 LLM + L-subclass 模板，
    结果经过 IR 字段来源守卫检查（不得引用 IR 未声明的字段）。

    Usage:
        gen = ZlintCodeGenerator(api_key="...", api_base="...", model="...")
        result = gen.generate(ir_dict)  # returns CodeGenResult
    """

    def __init__(
        self,
        api_key: str = "",
        api_base: str = "https://rsxermu666.cn/v1",
        model: str = "Qwen/Qwen3-8B",
        zlint_lints_dir: Optional[Path] = None,
        max_retries: int = 3,
        rate_limit_rpm: int = 100,
    ):
        self.api_key = api_key
        self.api_base = api_base
        self.model = model
        self.provider = resolve_llm_provider(
            provider=os.getenv("LLM_PROVIDER"),
            api_base=api_base,
        )
        self.max_retries = max_retries
        self.rate_limit_rpm = rate_limit_rpm
        self._last_call_time = 0.0

        self.template_lib = LSubclassTemplateLibrary()

        # Zlint source directory for few-shot examples
        if zlint_lints_dir is None:
            backend_dir = Path(__file__).parent.parent.parent
            zlint_lints_dir = backend_dir / "zlint" / "v3" / "lints"
        self.zlint_lints_dir = zlint_lints_dir

    # ----------------------------------------------------------
    # Core generation
    # ----------------------------------------------------------

    def generate(self, ir: Dict[str, Any]) -> CodeGenResult:
        """Generate zlint Go code for a single IR rule.

        Args:
            ir: Complete IR dict (from golden data or extraction pipeline)

        Returns:
            CodeGenResult with success/failure and generated code
        """
        t0 = time.time()
        rule_id = ir.get("rule_id", "unknown")

        # Step 1: Check lintability
        lint_subclass = ir.get("lint_subclass")
        if not ir.get("lintable") or not lint_subclass:
            return CodeGenResult(
                rule_id=rule_id,
                lint_name="",
                lint_subclass=lint_subclass or "",
                success=False,
                error="Rule is not lintable or has no lint_subclass",
            )

        # Step 2: Get template
        template = self.template_lib.get_template(lint_subclass)
        if not template:
            return CodeGenResult(
                rule_id=rule_id,
                lint_name="",
                lint_subclass=lint_subclass,
                success=False,
                error=f"No template for subclass {lint_subclass}",
            )

        # Step 3: Extract metadata (lint_name, description from rule_text, etc.)
        metadata = LSubclassTemplateLibrary.ir_to_metadata(ir)

        # Step 4: Select few-shot examples
        examples = select_few_shot_examples(
            package=metadata["package"],
            lint_subclass=lint_subclass,
            zlint_lints_dir=self.zlint_lints_dir,
            max_examples=2,
        )

        # Step 5: Build prompt
        prompt = build_codegen_prompt(ir, metadata, template, examples)

        # Step 6: Call LLM
        try:
            response = self._call_llm(prompt)
        except Exception as e:
            return CodeGenResult(
                rule_id=rule_id,
                lint_name=metadata["lint_name"],
                lint_subclass=lint_subclass,
                success=False,
                metadata=metadata,
                error=f"LLM call failed: {e}",
                generation_time_ms=(time.time() - t0) * 1000,
                description_from_ir=metadata["description"],
            )

        # Step 7: Parse response
        go_code, llm_params, parse_error = parse_codegen_response(response)
        if not go_code:
            return CodeGenResult(
                rule_id=rule_id,
                lint_name=metadata["lint_name"],
                lint_subclass=lint_subclass,
                success=False,
                metadata=metadata,
                llm_params=llm_params,
                error=f"Parse failed: {parse_error}",
                generation_time_ms=(time.time() - t0) * 1000,
                description_from_ir=metadata["description"],
            )

        # Step 8: Postprocess (fix description, lint_name, citation deterministically)
        go_code = postprocess_go_code(go_code, metadata)

        # Step 9: Generate test code
        test_code = self._generate_test_code(metadata)

        return CodeGenResult(
            rule_id=rule_id,
            lint_name=metadata["lint_name"],
            lint_subclass=lint_subclass,
            success=True,
            go_code=go_code,
            test_code=test_code,
            metadata=metadata,
            llm_params=llm_params,
            generation_time_ms=(time.time() - t0) * 1000,
            description_from_ir=metadata["description"],
        )

    # ----------------------------------------------------------
    # Batch generation
    # ----------------------------------------------------------

    def generate_batch(
        self,
        rules: List[Dict[str, Any]],
        output_dir: Optional[Path] = None,
        progress_callback=None,
    ) -> BatchCodeGenResult:
        """Generate code for a batch of IR rules.

        Args:
            rules: List of IR dicts (must have lintable=True)
            output_dir: If set, save .go files here
            progress_callback: Called with (index, total, result) after each rule
        """
        t0 = time.time()
        batch_result = BatchCodeGenResult(total=len(rules))

        for i, ir in enumerate(rules):
            if not ir.get("lintable"):
                batch_result.skipped += 1
                continue

            result = self.generate(ir)
            batch_result.results.append(result)

            if result.success:
                batch_result.success += 1
                if output_dir:
                    self._save_generated_lint(result, output_dir)
            else:
                batch_result.failed += 1

            if progress_callback:
                progress_callback(i + 1, len(rules), result)

        batch_result.total_time_s = time.time() - t0
        return batch_result

    # ----------------------------------------------------------
    # LLM call
    # ----------------------------------------------------------

    def _call_llm(self, prompt: str) -> str:
        """Call LLM API with rate limiting and retry."""
        # Rate limiting
        min_interval = 60.0 / self.rate_limit_rpm
        elapsed = time.time() - self._last_call_time
        if elapsed < min_interval:
            time.sleep(min_interval - elapsed)

        # Larger max_tokens for code generation
        max_tokens = 8000 if "Qwen" in self.model else 8192
        system_prompt = "You are a Go code generator for zlint v3 certificate lints."
        timeout = 300.0 if self.provider == "anthropic" else 120.0

        for attempt in range(self.max_retries + 1):
            try:
                self._last_call_time = time.time()
                return call_text_completion(
                    prompt,
                    model=self.model,
                    api_key=self.api_key,
                    api_base=self.api_base,
                    provider=self.provider,
                    system_prompt=system_prompt,
                    temperature=0,
                    max_tokens=max_tokens,
                    max_retries=0,
                    timeout=timeout,
                )
            except Exception as e:
                message = str(e)
                is_retryable = any(code in message for code in ("HTTP 429", "HTTP 529"))
                is_retryable = is_retryable or isinstance(e, (httpx.TimeoutException, httpx.ConnectError))
                if is_retryable and attempt < self.max_retries:
                    if "HTTP 429" in message or "HTTP 529" in message:
                        delay = (2 ** attempt) * 8 + random.uniform(0, 5)
                    else:
                        delay = (2 ** attempt) * 2
                    time.sleep(delay)
                    continue
                raise

    # ----------------------------------------------------------
    # Helpers
    # ----------------------------------------------------------

    @staticmethod
    def _generate_test_code(metadata: Dict[str, str]) -> str:
        """Generate basic test code for the lint."""
        sn = metadata["struct_name"]
        pkg = metadata["package"]
        return f'''package {pkg}

import (
\t"testing"
\t"github.com/zmap/zlint/v3/lint"
)

func TestNew{sn}(t *testing.T) {{
\tl := New{sn}()
\tif l == nil {{
\t\tt.Fatalf("expected non-nil lint")
\t}}
}}
'''

    # ========== compat wrappers (bridge old code using .generate_from_ir / .generate_from_ir_dict) ==========
    def generate_from_ir(self, ir: Dict[str, Any]) -> Dict[str, Any]:
        """Compat: convert old dict IR → new CodeGenResult → back to old dict format."""
        result = self.generate(ir)  # generate returns CodeGenResult
        return self._codegen_result_to_dict(result)

    def generate_from_ir_dict(self, ir: Dict[str, Any]) -> Tuple[str, str, str, Dict[str, Any]]:
        """Compat: keep old (go_code, test_code, ir_json, metadata) signature used by zlint_enhanced_routes."""
        result = self.generate(ir)
        return (
            result.go_code or "",
            result.test_code or "",
            json.dumps(result.ir_json or {}, ensure_ascii=False),
            result.metadata or {},
        )

    def _codegen_result_to_dict(self, result: CodeGenResult) -> Dict[str, Any]:
        """Convert CodeGenResult → legacy dict with 'success'/'go_code' keys."""
        if result.status in ("success", "llm_success"):
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
        """Save generated lint to .go file."""
        pkg = result.metadata.get("package", "rfc") if result.metadata else "rfc"
        pkg_dir = output_dir / pkg
        pkg_dir.mkdir(parents=True, exist_ok=True)

        # Main lint file
        filename = f"lint_{result.lint_name}.go"
        filepath = pkg_dir / filename
        filepath.write_text(result.go_code, encoding="utf-8")

        # Test file
        if result.test_code:
            test_filename = f"lint_{result.lint_name}_test.go"
            test_filepath = pkg_dir / test_filename
            test_filepath.write_text(result.test_code, encoding="utf-8")
