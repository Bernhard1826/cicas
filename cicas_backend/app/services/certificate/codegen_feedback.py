"""
Code Generation Feedback Loop

When verification fails, traces the failure back to the specific pipeline stage
and applies fixes (auto-fix for deterministic errors, re-generation for LLM errors).

Error taxonomy:
- Description mismatch → auto-fix (replace with IR rule_text)
- Section number wrong → auto-fix (replace with correct citation)
- Compilation error → re-generate with error context
- Wrong field expression → lookup target_path_mapper
- Semantic misalignment → re-generate with alignment feedback
- Wrong classification → flag for manual review
"""
import re
import time
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

from app.services.certificate.code_verification import (
    CodeVerificationPipeline,
    VerificationResult,
    AlignmentScore,
)
from app.services.certificate.zlint_generator import (
    ZlintCodeGenerator,
    CodeGenResult,
)
from app.services.certificate.l_subclass_templates import LSubclassTemplateLibrary


class ErrorStage(str, Enum):
    EXTRACTION = "extraction"
    TEMPLATE = "template"
    CODEGEN = "codegen"
    VERIFICATION = "verification"


class FixStrategy(str, Enum):
    AUTO_FIX = "auto_fix"
    REGENERATE = "regenerate"
    MANUAL = "manual"
    SKIP = "skip"


@dataclass
class ErrorClassification:
    """Classified error from verification."""
    stage: ErrorStage
    error_type: str
    description: str
    fix_strategy: FixStrategy
    auto_fix_fn: Optional[str] = None  # Name of auto-fix method
    root_cause: Optional[str] = None


@dataclass
class FeedbackIteration:
    """Record of one feedback iteration."""
    iteration: int
    errors_found: List[ErrorClassification] = field(default_factory=list)
    fixes_applied: List[str] = field(default_factory=list)
    verification_before: Optional[AlignmentScore] = None
    verification_after: Optional[AlignmentScore] = None
    regenerated: bool = False
    root_cause_stage: Optional[str] = None


@dataclass
class FeedbackResult:
    """Complete feedback loop result."""
    rule_id: str
    converged: bool = False
    final_code: Optional[str] = None
    final_score: float = 0.0
    iterations: List[FeedbackIteration] = field(default_factory=list)
    total_iterations: int = 0
    needs_manual_review: bool = False
    manual_review_reasons: List[str] = field(default_factory=list)
    total_time_ms: float = 0


class CodegenFeedbackLoop:
    """Iterative feedback loop for code generation improvement."""

    def __init__(
        self,
        generator: ZlintCodeGenerator,
        verifier: CodeVerificationPipeline,
        max_iterations: int = 3,
        convergence_threshold: float = 0.7,
    ):
        self.generator = generator
        self.verifier = verifier
        self.max_iterations = max_iterations
        self.convergence_threshold = convergence_threshold
        self.template_lib = LSubclassTemplateLibrary()

    def run(
        self,
        ir: Dict[str, Any],
        initial_code: str,
        section_text: str = "",
        source_text: str = "",
    ) -> FeedbackResult:
        """Run feedback loop on generated code.

        Args:
            ir: Original IR dict
            initial_code: Initially generated Go code
            section_text: Source section text for traceability
            source_text: Exact source rule text/span for semantic verification
        """
        t0 = time.time()
        rule_id = ir.get("rule_id", "unknown")
        result = FeedbackResult(rule_id=rule_id)
        current_code = initial_code

        for iteration in range(self.max_iterations):
            iter_record = FeedbackIteration(iteration=iteration + 1)

            # Verify current code
            verification = self.verifier.verify(
                go_code=current_code,
                ir=ir,
                section_text=section_text,
                source_text=source_text,
                run_llm_judge=(iteration == 0),  # Only run LLM judge on first iteration
                run_reverse_ir=(iteration == 0),
            )
            iter_record.verification_before = verification.alignment

            # Check convergence
            if verification.alignment.overall_score >= self.convergence_threshold:
                result.converged = True
                result.final_code = current_code
                result.final_score = verification.alignment.overall_score
                result.iterations.append(iter_record)
                break

            # Classify errors
            errors = self._classify_errors(verification, ir, current_code)
            iter_record.root_cause_stage = self._earliest_stage(errors)
            iter_record.errors_found = errors

            if not errors:
                # No actionable errors but score below threshold
                result.final_code = current_code
                result.final_score = verification.alignment.overall_score
                result.iterations.append(iter_record)
                break

            # Apply fixes
            code_changed = False
            needs_regen = False

            for error in errors:
                if error.fix_strategy == FixStrategy.AUTO_FIX:
                    fixed_code = self._apply_auto_fix(current_code, error, ir)
                    if fixed_code != current_code:
                        current_code = fixed_code
                        code_changed = True
                        iter_record.fixes_applied.append(
                            f"auto_fix:{error.error_type}"
                        )

                elif error.fix_strategy == FixStrategy.REGENERATE:
                    needs_regen = True

                elif error.fix_strategy == FixStrategy.MANUAL:
                    result.needs_manual_review = True
                    result.manual_review_reasons.append(error.description)

            # Re-generate if needed
            if needs_regen and not code_changed:
                regen_code = self._regenerate_with_feedback(
                    ir, current_code, errors
                )
                if regen_code and regen_code != current_code:
                    current_code = regen_code
                    iter_record.regenerated = True
                    code_changed = True

            # Re-verify after fixes
            if code_changed:
                post_verify = self.verifier.verify(
                    go_code=current_code,
                    ir=ir,
                    section_text=section_text,
                    source_text=source_text,
                    run_llm_judge=False,
                    run_reverse_ir=False,
                )
                iter_record.verification_after = post_verify.alignment

            result.iterations.append(iter_record)

            if not code_changed:
                break  # No progress possible

        if not result.converged:
            result.final_code = current_code
            # Get final score
            final_v = self.verifier.verify(
                current_code,
                ir,
                section_text,
                source_text=source_text,
                run_llm_judge=False,
                run_reverse_ir=False,
            )
            result.final_score = final_v.alignment.overall_score

        result.total_iterations = len(result.iterations)
        result.total_time_ms = (time.time() - t0) * 1000
        return result

    # ----------------------------------------------------------
    # Error classification
    # ----------------------------------------------------------

    def _classify_errors(
        self, verification: VerificationResult, ir: Dict[str, Any], code: str
    ) -> List[ErrorClassification]:
        """Classify verification failures into actionable errors."""
        errors = []
        metadata = self.template_lib.ir_to_metadata(ir)
        template = self.template_lib.get_template(ir.get("lint_subclass", ""))
        lintability = ir.get("zlint_lintability") or {}

        # Upstream classification / template issues
        if lintability.get("can_generate") is False:
            errors.append(ErrorClassification(
                stage=ErrorStage.EXTRACTION,
                error_type="wrong_classification",
                description="IR marks rule as non-generatable but code generation was attempted",
                fix_strategy=FixStrategy.MANUAL,
                root_cause="deterministic_classification",
            ))

        if not ir.get("lint_subclass"):
            errors.append(ErrorClassification(
                stage=ErrorStage.TEMPLATE,
                error_type="missing_subclass",
                description="No executable subclass assigned for generated rule",
                fix_strategy=FixStrategy.MANUAL,
                root_cause="subclass_selection",
            ))
        elif template is None:
            errors.append(ErrorClassification(
                stage=ErrorStage.TEMPLATE,
                error_type="unsupported_subclass",
                description=f"No template registered for subclass {ir.get('lint_subclass')}",
                fix_strategy=FixStrategy.MANUAL,
                root_cause="template_coverage",
            ))

        # Structural errors
        if not verification.structural.has_init:
            errors.append(ErrorClassification(
                stage=ErrorStage.CODEGEN,
                error_type="missing_init",
                description="Missing init() function",
                fix_strategy=FixStrategy.REGENERATE,
                root_cause="code_generation",
            ))

        if not verification.structural.has_check_applies:
            errors.append(ErrorClassification(
                stage=ErrorStage.CODEGEN,
                error_type="missing_check_applies",
                description="Missing CheckApplies() function",
                fix_strategy=FixStrategy.REGENERATE,
                root_cause="code_generation",
            ))

        if not verification.structural.has_execute:
            errors.append(ErrorClassification(
                stage=ErrorStage.CODEGEN,
                error_type="missing_execute",
                description="Missing Execute() function",
                fix_strategy=FixStrategy.REGENERATE,
                root_cause="code_generation",
            ))

        # Compilation errors
        if not verification.structural.compiles and verification.structural.compile_error:
            errors.append(ErrorClassification(
                stage=ErrorStage.CODEGEN,
                error_type="compilation_error",
                description=f"Compilation: {verification.structural.compile_error[:200]}",
                fix_strategy=FixStrategy.REGENERATE,
                root_cause="code_generation",
            ))

        # Provenance / metadata issues
        if not verification.traceability.match_type or verification.traceability.match_type == "none":
            errors.append(ErrorClassification(
                stage=ErrorStage.EXTRACTION,
                error_type="description_mismatch",
                description="Description not traceable to source text",
                fix_strategy=FixStrategy.AUTO_FIX,
                auto_fix_fn="fix_description",
                root_cause="source_provenance",
            ))

        citation = self._extract_metadata_field("Citation", code)
        if citation is not None and citation != metadata.get("citation"):
            errors.append(ErrorClassification(
                stage=ErrorStage.TEMPLATE,
                error_type="citation_mismatch",
                description=f"Citation does not match deterministic metadata ({metadata.get('citation')})",
                fix_strategy=FixStrategy.AUTO_FIX,
                auto_fix_fn="fix_citation",
                root_cause="citation_mapping",
            ))

        source_value = self._extract_source_constant(code)
        if source_value is not None and source_value != metadata.get("source"):
            errors.append(ErrorClassification(
                stage=ErrorStage.TEMPLATE,
                error_type="source_mismatch",
                description=f"Source constant does not match deterministic metadata ({metadata.get('source')})",
                fix_strategy=FixStrategy.AUTO_FIX,
                auto_fix_fn="fix_source",
                root_cause="source_mapping",
            ))

        # Semantic alignment
        if verification.semantic.confidence > 0 and not verification.semantic.overall_aligned:
            if not verification.semantic.field_correct:
                errors.append(ErrorClassification(
                    stage=ErrorStage.TEMPLATE,
                    error_type="wrong_field",
                    description="Code checks wrong certificate field",
                    fix_strategy=FixStrategy.REGENERATE,
                    root_cause="template_or_field_mapping",
                ))
            elif not verification.semantic.logic_correct:
                errors.append(ErrorClassification(
                    stage=ErrorStage.CODEGEN,
                    error_type="wrong_logic",
                    description="Code logic does not match spec requirement",
                    fix_strategy=FixStrategy.REGENERATE,
                    root_cause="code_generation",
                ))
            elif verification.semantic.semantic_gaps:
                errors.append(ErrorClassification(
                    stage=ErrorStage.EXTRACTION,
                    error_type="semantic_gap",
                    description=f"Gaps: {'; '.join(verification.semantic.semantic_gaps[:3])}",
                    fix_strategy=FixStrategy.REGENERATE,
                    root_cause="incomplete_ir_or_prompt",
                ))

            if verification.semantic.hallucinated_checks:
                errors.append(ErrorClassification(
                    stage=ErrorStage.CODEGEN,
                    error_type="hallucinated_checks",
                    description=f"Hallucinated: {'; '.join(verification.semantic.hallucinated_checks[:3])}",
                    fix_strategy=FixStrategy.REGENERATE,
                    root_cause="code_generation",
                ))

            if not verification.semantic.obligation_correct:
                errors.append(ErrorClassification(
                    stage=ErrorStage.TEMPLATE,
                    error_type="wrong_obligation",
                    description="Lint severity / obligation does not match source requirement",
                    fix_strategy=FixStrategy.MANUAL,
                    root_cause="classification_or_metadata",
                ))

        return errors

    # ----------------------------------------------------------
    # Auto-fix methods
    # ----------------------------------------------------------

    def _apply_auto_fix(
        self, code: str, error: ErrorClassification, ir: Dict[str, Any]
    ) -> str:
        """Apply deterministic auto-fix."""
        if error.auto_fix_fn == "fix_description":
            return self._fix_description(code, ir)
        if error.auto_fix_fn == "fix_citation":
            return self._fix_citation(code, ir)
        if error.auto_fix_fn == "fix_source":
            return self._fix_source(code, ir)
        return code

    def _fix_description(self, code: str, ir: Dict[str, Any]) -> str:
        """Replace Description with IR's rule_text."""
        rule_text = ir.get("rule_text", "")
        if not rule_text:
            c = ir.get("constraint", {})
            rule_text = c.get("raw_text", "") if isinstance(c, dict) else ""
        if not rule_text:
            return code

        # Escape for Go string
        escaped = rule_text.replace('"', '\\"').replace("\n", " ").strip()
        if len(escaped) > 500:
            escaped = escaped[:497] + "..."

        return re.sub(
            r'Description:\s*"[^"]*"',
            f'Description:   "{escaped}"',
            code,
        )

    def _fix_citation(self, code: str, ir: Dict[str, Any]) -> str:
        """Replace Citation with deterministic metadata citation."""
        citation = self.template_lib.ir_to_metadata(ir).get("citation", "")
        if not citation:
            return code
        escaped = citation.replace('"', '\\"').strip()
        return re.sub(
            r'Citation:\s*"[^"]*"',
            f'Citation:      "{escaped}"',
            code,
        )

    def _fix_source(self, code: str, ir: Dict[str, Any]) -> str:
        """Replace Source with deterministic metadata source constant."""
        source_const = self.template_lib.ir_to_metadata(ir).get("source", "")
        if not source_const:
            return code
        return re.sub(
            r'Source:\s*lint\.[A-Za-z0-9_]+',
            f'Source:        lint.{source_const}',
            code,
        )

    def _extract_metadata_field(self, field_name: str, code: str) -> Optional[str]:
        """Extract a string-valued lint metadata field from generated Go code."""
        match = re.search(rf'{field_name}:\s*"([^"]*)"', code)
        return match.group(1).strip() if match else None

    def _extract_source_constant(self, code: str) -> Optional[str]:
        """Extract lint.Source constant from generated Go code."""
        match = re.search(r'Source:\s*lint\.([A-Za-z0-9_]+)', code)
        return match.group(1).strip() if match else None

    def _earliest_stage(self, errors: List[ErrorClassification]) -> Optional[str]:
        """Return the earliest likely failing stage for a set of errors."""
        stage_order = [
            ErrorStage.EXTRACTION,
            ErrorStage.TEMPLATE,
            ErrorStage.CODEGEN,
            ErrorStage.VERIFICATION,
        ]
        for stage in stage_order:
            if any(error.stage == stage for error in errors):
                return stage.value
        return None

    # ----------------------------------------------------------
    # Re-generation with feedback
    # ----------------------------------------------------------

    def _regenerate_with_feedback(
        self,
        ir: Dict[str, Any],
        current_code: str,
        errors: List[ErrorClassification],
    ) -> Optional[str]:
        """Re-generate code with error context in prompt."""
        error_context = "\n".join(
            f"- {e.error_type}: {e.description}"
            for e in errors
            if e.fix_strategy == FixStrategy.REGENERATE
        )

        # Add error context to the IR as a hint for the generator
        ir_with_feedback = dict(ir)
        ir_with_feedback["_feedback_errors"] = error_context
        ir_with_feedback["_previous_code"] = current_code[:1000]

        result = self.generator.generate(ir_with_feedback)
        return result.go_code if result.success else None
