"""
LLM Prompt Templates for zlint Code Generation

Provides prompt construction, few-shot example selection, and response parsing
for template-guided LLM code generation.
"""
import json
import re
from typing import Dict, List, Optional, Any, Tuple
from pathlib import Path


# ============================================================
# System prompt
# ============================================================

CODEGEN_SYSTEM_PROMPT = """You are a Go code generator specialized in X.509 certificate linting.
You generate zlint v3 lint implementations from structured rule descriptions.

HARD CONSTRAINTS (violations = automatic rejection):
1. The Description field MUST be EXACTLY the text provided — do NOT paraphrase.
2. The Citation field MUST match the provided citation.
3. The code MUST compile against zlint v3 (github.com/zmap/zlint/v3).
4. Use ONLY these imports: x509, lint, util (from zlint), plus Go stdlib as needed.
5. The Execute() function MUST return *lint.LintResult with Status field.
6. CheckApplies() MUST return false for certificates the rule does not apply to.

OUTPUT FORMAT:
Return ONLY the parameter values as a JSON object, then the complete Go code in a ```go block.
"""


# ============================================================
# Per-subclass prompt templates
# ============================================================

def build_codegen_prompt(
    ir: Dict[str, Any],
    metadata: Dict[str, str],
    template: Any,  # LSubclassTemplate
    few_shot_examples: List[str],
) -> str:
    """Build the LLM prompt for code generation.

    Args:
        ir: Full IR dict for the rule
        metadata: From LSubclassTemplateLibrary.ir_to_metadata()
        template: LSubclassTemplate for the rule's L-subclass
        few_shot_examples: 1-3 existing zlint Go code snippets

    Returns:
        Complete prompt string
    """
    # --- Section A: Rule context ---
    section_a = f"""## Rule Context
- Source: {metadata['source_id']} Section {metadata['section']}
- Rule ID: {ir.get('rule_id', 'unknown')}
- Description (USE VERBATIM): "{metadata['description']}"
- Citation: {metadata['citation']}
- Package: {metadata['package']}
- Severity: {metadata['fail_status']}
- Lint name: {metadata['lint_name']}
"""

    # --- Section B: Structured IR ---
    subject = ir.get("subject", {})
    subject_path = subject.get("path", "") if isinstance(subject, dict) else str(subject)
    obligation = ir.get("obligation", "MUST")
    predicate = ir.get("predicate", "")
    constraint = ir.get("constraint", {})
    constraint_raw = constraint.get("raw_text", "") if isinstance(constraint, dict) else str(constraint)
    constraint_type = constraint.get("type", "") if isinstance(constraint, dict) else ""
    constraint_value = constraint.get("value", "") if isinstance(constraint, dict) else ""
    precondition = ir.get("precondition")

    section_b = f"""## Structured IR (Extracted Rule)
- Subject: {subject_path}
- Obligation: {obligation}
- Predicate: {predicate}
- Constraint type: {constraint_type}
- Constraint value: {constraint_value}
- Constraint text: {constraint_raw}
- Rule category: {ir.get('rule_category', '')}
- Lint subclass: {ir.get('lint_subclass', '')}
"""
    if precondition:
        section_b += f"- Precondition: {json.dumps(precondition, ensure_ascii=False)}\n"

    # --- Section C: Template ---
    param_desc = "\n".join(
        f"  - {p.name}: {p.description} (example: {p.example})"
        for p in template.params
    )
    section_c = f"""## Code Template ({template.subclass}: {template.description})

Template parameters to fill:
{param_desc}

Template notes:
{template.notes}

Execute body template:
```
{template.execute_template}
```
"""

    # --- Section D: Few-shot examples ---
    section_d = ""
    if few_shot_examples:
        section_d = "## Reference Examples (existing zlint lints for this package)\n\n"
        for i, ex in enumerate(few_shot_examples, 1):
            # Truncate long examples
            if len(ex) > 1500:
                ex = ex[:1500] + "\n// ... (truncated)"
            section_d += f"### Example {i}:\n```go\n{ex}\n```\n\n"

    # --- Section E: Output instructions ---
    section_e = f"""## Output Instructions

1. First, output a JSON object with the filled template parameters:
```json
{{
  "CHECK_APPLIES_EXPR": "Go boolean expression for CheckApplies",
  "EXECUTE_BODY": "Complete Go code for Execute() body",
  "EXTRA_IMPORTS": ["any additional Go imports needed"]
}}
```

2. Then, output the COMPLETE Go file:
```go
// ... complete Go source code ...
```

REMEMBER:
- Description MUST be exactly: "{metadata['description'][:200]}"
- The code must be a valid zlint v3 lint that compiles.
- CheckApplies should return true only for certificates this rule applies to.
- Use the certificate field: {subject_path}
"""

    return CODEGEN_SYSTEM_PROMPT + "\n" + section_a + section_b + section_c + section_d + section_e


# ============================================================
# Response parsing
# ============================================================

def parse_codegen_response(response: str) -> Tuple[Optional[str], Optional[Dict], str]:
    """Parse LLM response to extract Go code and parameters.

    Returns:
        (go_code, params_dict, error_message)
    """
    errors = []

    # Extract JSON parameters block
    params = None
    json_match = re.search(r'```json\s*\n(.*?)\n\s*```', response, re.DOTALL)
    if json_match:
        try:
            params = json.loads(json_match.group(1))
        except json.JSONDecodeError as e:
            errors.append(f"JSON parse error: {e}")

    # Extract Go code block
    go_code = None
    go_match = re.search(r'```go\s*\n(.*?)\n\s*```', response, re.DOTALL)
    if go_match:
        go_code = go_match.group(1).strip()
    else:
        # Try to find code without markdown markers
        if "package " in response and "func init()" in response:
            # Find the start of Go code
            pkg_idx = response.index("package ")
            # Find the last closing brace
            last_brace = response.rfind("}")
            if last_brace > pkg_idx:
                go_code = response[pkg_idx:last_brace + 1].strip()

    if not go_code:
        errors.append("No Go code block found in response")

    return go_code, params, "; ".join(errors) if errors else ""


# ============================================================
# Few-shot example selection
# ============================================================

def select_few_shot_examples(
    package: str,
    lint_subclass: str,
    zlint_lints_dir: Path,
    max_examples: int = 2,
) -> List[str]:
    """Select existing zlint lints as few-shot examples.

    Prioritizes lints from the same package that are structurally similar
    to the target subclass.
    """
    examples = []
    lint_dir = zlint_lints_dir / package
    if not lint_dir.exists():
        # Fallback to rfc package
        lint_dir = zlint_lints_dir / "rfc"
        if not lint_dir.exists():
            return []

    # Map subclass to Go code patterns we want to match
    subclass_patterns = {
        "L1": ["IsExtInCert", "== nil"],
        "L2": ["!= ", "== ", "Critical"],
        "L3": ["map[", "switch "],
        "L4": ["regexp.", "asn1.", "encoding"],
        "L5": ["Contains", "range ", "for _,"],
        "L6": ["BitLen", ">= ", "<= "],
        "L7": ["if c.IsCA", "if util.Is"],
    }
    patterns = subclass_patterns.get(lint_subclass, [])

    # Scan lint files and score by relevance
    scored = []
    for go_file in lint_dir.glob("lint_*.go"):
        if go_file.name.endswith("_test.go"):
            continue
        try:
            content = go_file.read_text(encoding="utf-8")
            if len(content) > 3000:
                continue  # Skip very long files
            score = sum(1 for p in patterns if p in content)
            if score > 0:
                scored.append((score, content, go_file.name))
        except Exception:
            continue

    # Sort by score descending, take top N
    scored.sort(key=lambda x: x[0], reverse=True)
    for _, content, _ in scored[:max_examples]:
        examples.append(content)

    # If not enough, take any short lint from the package
    if len(examples) < max_examples:
        for go_file in lint_dir.glob("lint_*.go"):
            if go_file.name.endswith("_test.go"):
                continue
            if len(examples) >= max_examples:
                break
            try:
                content = go_file.read_text(encoding="utf-8")
                if len(content) <= 2000 and content not in examples:
                    examples.append(content)
            except Exception:
                continue

    return examples[:max_examples]


# ============================================================
# Post-processing: fix common LLM mistakes
# ============================================================

def postprocess_go_code(
    go_code: str,
    metadata: Dict[str, str],
) -> str:
    """Fix common LLM mistakes in generated Go code.

    Deterministic fixes that don't require re-generation:
    - Wrong description → replace with correct one
    - Wrong lint name → replace with correct one
    - Wrong package → replace with correct one
    - Missing/wrong imports → auto-detect and fix
    """
    if not go_code:
        return go_code

    # Fix description (most critical — must be verbatim original text)
    desc_pattern = r'Description:\s*"([^"]*)"'
    correct_desc = metadata["description"]
    go_code = re.sub(desc_pattern, f'Description:   "{correct_desc}"', go_code)

    # Fix lint name
    name_pattern = r'Name:\s*"([^"]*)"'
    go_code = re.sub(name_pattern, f'Name:          "{metadata["lint_name"]}"', go_code)

    # Fix citation
    cite_pattern = r'Citation:\s*"([^"]*)"'
    go_code = re.sub(cite_pattern, f'Citation:      "{metadata["citation"]}"', go_code)

    # Fix source
    source_pattern = r'Source:\s*lint\.(\w+)'
    go_code = re.sub(source_pattern, f'Source:        lint.{metadata["source"]}', go_code)

    # Fix package declaration
    pkg_pattern = r'^package \w+'
    go_code = re.sub(pkg_pattern, f'package {metadata["package"]}', go_code, count=1)

    return go_code
