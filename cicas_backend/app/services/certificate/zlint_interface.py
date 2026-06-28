"""
zlint Interface

ZLint Coverage Detection V2 (Updated 2025-12-20):
- New three-step matching process:
  1. Source matching (document source mapping)
  2. Citation section matching (section number extraction from raw citation)
  3. LLM synonym judgment (same certificate field/check topic)

Also manages zlint installation and execution for direct coverage analysis.
"""
import os
import subprocess
import json
import tempfile
import re
import asyncio
import httpx
from typing import Dict, List, Optional, Set
from pathlib import Path

from app.core.logging_config import app_logger
from app.core.config import settings
from app.services.certificate.zlint_generator import ZlintCodeGenerator
from app.services.certificate.zlint_citation_parser import ZLintCitationParser, ZLintMetadata
from app.utils.llm_client import LLMClient
from sqlalchemy.orm import Session


class ZLintInterface:
    """
    Interface to zlint for precise certificate validation
    """

    def __init__(self, zlint_path: str = None, cloud_llm_caller=None):
        self.zlint_path = zlint_path or settings.zlint_path
        self.zlint_binary = self._find_zlint_binary()
        self.generator = ZlintCodeGenerator()  # 全量 LLM 路径
        self._existing_citations_cache = None  # Cache for existing lint citations
        self._existing_lints_cache = None  # Cache for all existing lints info

        # ========== V3: Citation + LLM Coverage Detection ==========
        # Citation 解析器（从 zlint_path 派生 lints 目录路径）
        from pathlib import Path
        self.zlint_lints_path = str(Path(self.zlint_path) / 'v3' / 'lints')
        self.citation_parser = ZLintCitationParser(zlint_root=self.zlint_lints_path)

        # LLM 客户端（用于第3层同义判断）
        self.llm_client = LLMClient(
            model=settings.llm_model,
            temperature=0.0,
            max_tokens=20
        )

        # ZLint 元数据（需要调用 initialize_coverage_detection() 来填充）
        self.all_zlint_metadata: List[ZLintMetadata] = []
        self.zlint_metadata_dict: Dict[str, ZLintMetadata] = {}

        # zlint 反向 IR（subject/obligation/predicate/constraint/applies_to/summary，
        # 从 zlint 源码反抽取，results/lint_ir_summaries.json）。覆盖判别按 source 缩小
        # 候选：RFC 规则↔RFC lint 按章节匹配；CABF-BR 规则↔全部 CABF-BR lint（章节会漂移）。
        # 不用 embedding —— 收窄到 zlint 单工具后按 source 结构分区即可。
        self.zlint_ir_rfc: List[Dict] = []
        self.zlint_ir_cabf: List[Dict] = []

        # 初始化标志
        self._coverage_initialized = False

        app_logger.info(
            f"[ZLintInterface] Initialized (V4: DSL Tree Matching)"
        )

    def _find_zlint_binary(self) -> Optional[str]:
        """Find zlint binary in system"""
        import platform

        binary_name = 'zlint.exe' if platform.system() == 'Windows' else 'zlint'
        location = os.path.join(self.zlint_path, 'v3', binary_name)

        try:
            result = subprocess.run(
                [location, '-version'],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0:
                app_logger.info(f"Found zlint at: {location}")
                return location
        except Exception:
            pass

        app_logger.warning(f"zlint binary not found at {location} (coverage checking will still work with cache)")
        return None

    async def initialize_coverage_detection(self):
        """
        初始化覆盖检测：解析 zlint 源码元数据

        必须在使用 check_rule_coverage_intelligent() 前调用！
        """
        if self._coverage_initialized:
            app_logger.debug("[ZLintInterface] Coverage detection already initialized")
            return

        app_logger.info("[ZLintInterface] Initializing coverage detection (V3: Citation + LLM)...")

        # 解析所有 zlint 元数据
        self.all_zlint_metadata = self.citation_parser.parse_all_lints()
        self.zlint_metadata_dict = self.citation_parser.get_metadata_dict(self.all_zlint_metadata)

        app_logger.info(f"[ZLintInterface] Loaded {len(self.all_zlint_metadata)} zlint metadata")

        # 加载 zlint 反向 IR（覆盖判别用）
        self._load_zlint_irs()

        self._coverage_initialized = True
        app_logger.info("[ZLintInterface] Coverage detection initialization complete!")

    def _load_zlint_irs(self):
        """加载 zlint 反向 IR（subject/obligation/predicate/constraint/applies_to/summary），
        按 source 分到 RFC / CABF-BR 两组，并预解析每条 lint 的 citation 章节号。"""
        candidates = [
            Path(__file__).resolve().parents[2] / "experiments" / "results" / "lint_ir_summaries.json",
            Path(__file__).resolve().parents[3] / "experiments" / "results" / "lint_ir_summaries.json",
        ]
        path = next((p for p in candidates if p.exists()), None)
        if not path:
            app_logger.warning("[ZLintInterface] lint_ir_summaries.json not found; coverage judge has no zlint IRs")
            return
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except Exception as e:
            app_logger.error(f"[ZLintInterface] failed to load zlint IRs: {e}")
            return
        sect_re = re.compile(r'\d+(?:\.\d+)+|\d+')
        self.zlint_ir_rfc, self.zlint_ir_cabf = [], []
        for z in data:
            if z.get("tool") != "zlint":
                continue
            z["_sect"] = set(sect_re.findall(str(z.get("_raw_citation") or "")))
            src = z.get("_raw_source") or ""
            if src.startswith("zlint/rfc"):
                self.zlint_ir_rfc.append(z)
            elif src.startswith("zlint/cabf_br"):
                self.zlint_ir_cabf.append(z)
        app_logger.info(
            f"[ZLintInterface] Loaded zlint IRs for coverage: RFC={len(self.zlint_ir_rfc)} CABF-BR={len(self.zlint_ir_cabf)} from {path.name}"
        )

    # Validated field-by-field coverage judge (ported from the audited experiment
    # coverage_analysis.py — 14/14 correct on `full`, 0 false positives). Compares
    # the rule's IR against the candidate zlint lint IRs FIELD BY FIELD; enforces the
    # constraint-VALUE discipline (different value/target/sub-field/artifact on the
    # same topic = none) that the old loose "same topic" judge lacked.
    _COVERAGE_JUDGE = """You decide whether an EXISTING zlint check implements a normative
requirement, by comparing their intermediate representations (IR) FIELD BY FIELD.

This is NOT a "related topic" test. The lint covers the requirement only if their
IR fields correspond — same field, same obligation direction, same constraint.

Align and compare these fields for each candidate:
    requirement.text         <->  lint.summary
    requirement.subject      <->  lint.subject        (which field / extension / bit)
    requirement.obligation   <->  lint.obligation     (MUST / MUST_NOT / SHOULD ...)
    requirement.predicate    <->  lint.predicate
    requirement.constraint   <->  lint.constraint     (value / threshold / type)
    requirement.precondition <->  lint.applies_to     (applicability / scope)

Judge obligation + predicate + constraint TOGETHER as one requirement. Two cases:

(1) SAME requirement re-encoded differently -> fields ALIGN (full):
  - "MUST be >= 0"  ==  "MUST NOT be < 0"            (same boundary)
  - "MUST be present"  ==  "MUST NOT be absent"      (same presence)
  - "if cA NOT asserted, keyCertSign MUST NOT be set" == "if keyCertSign set, cA MUST be asserted" (contrapositive)

(2) DIFFERENT requirement on the same field -> fields DIFFER (none), even though the
    topic/extension is the same. A shared field is NOT enough; the actual VALUE /
    TARGET / aspect must be the same:
  - prohibit explicitText = VisibleString/BMPString  is NOT  prohibit = IA5String
  - require SHA-256  is NOT  require SHA-384
  - an EXTENSION must be absent  is NOT  a SUB-FIELD of an extension must be absent
  - a check on a CRL  is NOT  a check on a certificate (different artifact)
Length vs value, presence vs criticality, "same extension different sub-field" = none.

Verdict (best level across all candidates):
  "full"    -> SAME subject/sub-field, SAME direction, SAME constraint value/target
               (or a provably identical re-encoding per case (1)).
  "partial" -> SAME subject and direction, lint is a STRICT SUBSET: narrower scope,
               one of several named conditions, or a stricter/weaker bound of the SAME constraint.
  "none"    -> different subject/sub-field/bit, different direction, a DIFFERENT
               constraint value/target/type (case (2)), different artifact, or incompatible applies_to.

=== NORMATIVE REQUIREMENT (IR) ===
text:         {text}
subject:      {subject}
obligation:   {obligation}
predicate:    {predicate}
constraint:   {constraint}
precondition: {precondition}

=== CANDIDATE zlint CHECKS (IR reverse-extracted from code) ===
{candidates}

=== OUTPUT ===
Compare the IRs FIELD BY FIELD and give a DETAILED reason in EVERY case (match or not).
Return ONLY JSON (verdict = best level reached across all candidates):
{{"verdict": "full" | "partial" | "none",
  "lint": "<rule_id of the best/covering candidate, or null if nothing related>",
  "fields": {{"subject":"<align|differ: state both>","obligation":"<align|differ>",
     "predicate":"<align|differ>","constraint":"<align|differ>","applies_to":"<align|differ>"}},
  "reason": "<detailed, field-grounded: if full/partial which fields align and why; if none, NAME the closest candidate (its rule_id) and say exactly which field(s) differ>"}}
For "none" you MUST still name the closest candidate and give the field-by-field reason — never leave it empty.
"""

    @staticmethod
    def _section_prefix_match(rule_sec: str, cited_sects: Set[str]) -> bool:
        rs = str(rule_sec or "").strip().strip(".")
        if not rs:
            return False
        rp = rs.split(".")
        for c in cited_sects:
            c = str(c).strip(".")
            if not c:
                continue
            cp = c.split(".")
            n = min(len(rp), len(cp))
            if n >= 1 and rp[:n] == cp[:n]:
                return True
        return False

    def _coverage_candidates(self, source: str, section: str) -> List[Dict]:
        """按 source 缩小候选（无 embedding）：
        RFC 规则 → RFC lint 中 citation 章节匹配的（章节稳定）；
        CABF-BR 规则 → 全部 CABF-BR lint（章节会随版本漂移，只能按 source 收窄）。"""
        src = (source or "").upper().strip()
        if src in ("RFC", "RFC5280", "RFC2459"):
            return [z for z in self.zlint_ir_rfc if self._section_prefix_match(section, z.get("_sect") or set())]
        if src in ("CABF", "CABF-BR", "CABF_BR", "BRS", "BR"):
            return list(self.zlint_ir_cabf)
        return []

    @staticmethod
    def _rule_ir_fields(rule: Dict) -> Dict:
        """从规则的 IR 取判别字段（subject/obligation/predicate/constraint/precondition）。"""
        ir = rule.get("ir")
        if not isinstance(ir, dict):
            ir_data = rule.get("ir_data")
            if isinstance(ir_data, str):
                try:
                    ir_data = json.loads(ir_data)
                except Exception:
                    ir_data = {}
            if isinstance(ir_data, dict):
                ir = ir_data.get("ir") if isinstance(ir_data.get("ir"), dict) else ir_data
        ir = ir or {}
        subj = ir.get("subject")
        subj = (subj.get("path") if isinstance(subj, dict) else subj) or ir.get("assertion_subject") or ""
        pre = ir.get("precondition")
        scope = " ".join(str(x) for x in (ir.get("enforcement_phase"),) if x)
        precond = (json.dumps(pre, ensure_ascii=False) if pre else "") + (f" [{scope}]" if scope else "")
        return {
            "text": (rule.get("text") or ir.get("rule_text") or "")[:400],
            "subject": subj,
            "obligation": ir.get("obligation"),
            "predicate": ir.get("predicate"),
            "constraint": json.dumps(ir.get("constraint"), ensure_ascii=False)[:300] if ir.get("constraint") else "",
            "precondition": precond[:300] or "(none)",
        }

    @staticmethod
    def _cand_block(cands: List[Dict]) -> str:
        out = []
        for i, z in enumerate(cands, 1):
            out.append(
                f"[{i}] rule_id={z.get('rule_id')}  severity={z.get('severity')}\n"
                f"    summary:     {(z.get('summary') or z.get('description') or '')[:200]}\n"
                f"    subject:     {z.get('subject')}\n"
                f"    obligation:  {z.get('obligation')}\n"
                f"    predicate:   {z.get('predicate')}\n"
                f"    constraint:  {z.get('constraint')}\n"
                f"    applies_to:  {z.get('applies_to')}"
            )
        return "\n".join(out)

    @staticmethod
    def _parse_judge_json(raw: str) -> Optional[Dict]:
        if not raw:
            return None
        s = re.sub(r'<think>.*?</think>\s*', '', raw, flags=re.DOTALL)
        m = re.search(r'\{.*\}', s, re.DOTALL)
        if not m:
            return None
        try:
            return json.loads(m.group(0))
        except Exception:
            return None

    # --- verdict consistency guard (deterministic subject-family check) ------
    # The audited CABF false positives returned verdict="full" matching a lint on
    # a DIFFERENT field (keyUsage rule -> e_ext_san_missing, version -> e_ca_is_ca).
    # The LLM's own align/differ label and prose are unreliable here (it wrote
    # "align" while describing two different fields), so we DON'T trust them. We
    # instead compare the rule's subject FAMILY against the matched lint's subject
    # FAMILY deterministically (same heuristic that surfaced the 36 mismatches):
    # if both resolve to a SPECIFIC, DIFFERENT field family, the "full" is spurious
    # -> downgrade. Vague/unresolved rule subjects (subject, certificate, an
    # operational noun) resolve to '' and are left alone (handled upstream by
    # lintability, not here) so genuine matches with a coarse rule subject survive.
    _SUBJECT_FAMILIES = {
        "authorityinfoaccess": "aia", "authoritykeyidentifier": "aki",
        "subjectkeyidentifier": "ski", "basicconstraints": "basicconstraints",
        "extkeyusage": "eku", "extendedkeyusage": "eku", "keyusage": "keyusage",
        "certificatepolicies": "certpol", "crldistributionpoints": "crldp",
        "freshestcrl": "freshestcrl", "nameconstraints": "nameconstraints",
        "policyconstraints": "policyconstraints", "policymappings": "policymappings",
        "subjectaltname": "san", "issueraltname": "ian", "subjectinfoaccess": "sia",
        "inhibitanypolicy": "inhibitany", "subjectdirectory": "subjdirattr",
        "serialnumber": "serial", "signaturealgorithm": "sigalg",
        "subjectpublickeyinfo": "spki", "organizationalunit": "ou",
        "organizationname": "orgname", "commonname": "cn", "countryname": "country",
        "stateorprovince": "state", "localityname": "locality", "validity": "validity",
        "version": "version", "nextupdate": "nextupdate", "thisupdate": "thisupdate",
        "crlnumber": "crlnumber", "issueruniqueid": "issueruid",
    }

    @classmethod
    def _subject_family(cls, s) -> str:
        """Map a subject path to a specific field family, or '' if vague/unresolved
        (subject / certificate / extensions / an operational noun)."""
        s = (str(s) if not isinstance(s, dict) else str(s.get("path") or "")).lower().replace("_", "")
        for tok, fam in cls._SUBJECT_FAMILIES.items():
            if tok in s:
                return fam
        return ""

    _RULE_THRESHOLDS = {
        "required":    ("must-not", "shall-not"),
        "forbidden":   ("want-not", "requested"),
        "prohibited":  ("must-not", "shall-not"),
        "required-presence":  ("must", "shall"),
        "forbidden-presence": ("must-not", "shall-not"),
    }

    @staticmethod
    def _obligation_polarity(text: str) -> int:
        """Classify rule as MUST (+1) / MAY (0) / MUST-NOT (-1).
        Only used as a rough gate in a deterministic safeguard.

        .*"""
        t = text.lower()
        if any(k in t for k in ("must not", "shall not", "must not be", "shall not be", "optional", "may", "extension is not required")):
            return -1          # prohibited presence (or optional → no positive obligation)
        if t.startswith("may") or "might" in t:
            return 0
        if any(k in t for k in ("must", "shall", "required")):
            return +1          # required presence
        return 0               # cannot determine → leave to LLM

    @classmethod
    def _consistent_verdict(cls, verdict: str, lint, lint_subject, rule_subject) -> str:
        """Downgrade full/partial when the rule and matched lint resolve to a
        SPECIFIC but DIFFERENT subject family (a wrong-field match) OR when
        the rule and lint imply opposite polarity (e.g., MUST NOT vs a positive presence)
        that機場。Never upgrades.  Deterministic — does not rely on the LLM's align/differ self-label."""
        if verdict in ("full", "partial"):
            if verdict == "full" and not lint:
                return "none"
            # Wrong-field match
            rf, lf = cls._subject_family(rule_subject), cls._subject_family(lint_subject)
            if rf and lf and rf != lf:
                return "none"      # wrong-field match
            # Obligation polarity: must-not rule matching a positive-presence lint (or vice versa)
            try:
                rule_text: str = rule_subject or ""
                lint_text: str = (lint.get("summary") for _ in ()) if lint else ""
            except Exception:
                rule_text = str(rule_subject)
                lint_text = str(lint.get("summary") or "") if lint else ""
            r_pol = cls._obligation_polarity(rule_text)
            l_pol = cls._obligation_polarity(lint_text)
            if r_pol == -1 and l_pol == +1:           # rule-prohibited → lint-expected: downgrade
                return "none"
            if r_pol == +1 and l_pol == -1:
                return "none"   # rule-required → lint-unexpected: downgrade
        return verdict

    _POLARITY = int

    async def _judge_coverage(self, rule_fields: Dict, candidates: List[Dict], batch: int = 40) -> Dict:
        """对一条规则的 IR 与候选 zlint lint IR 做字段级覆盖判别。
        候选过多（CABF 全集）时分批送 LLM，取跨批最优档（full > partial > none）。
        返回 {verdict, lint, fields, reason, n_cand}。无论匹配与否都带具体理由。"""
        if not candidates:
            return {"verdict": "none", "lint": None, "fields": {},
                    "reason": "No candidate zlint check was retrieved for this rule's source/section, "
                              "so nothing in zlint implements it.", "n_cand": 0}
        order = {"full": 2, "partial": 1, "none": 0}
        best = {"verdict": "none", "lint": None, "fields": {}, "reason": "", "n_cand": len(candidates)}
        for i in range(0, len(candidates), batch):
            chunk = candidates[i:i + batch]
            prompt = self._COVERAGE_JUDGE.format(candidates=self._cand_block(chunk), **rule_fields)
            try:
                raw = await asyncio.to_thread(self.llm_client.generate, prompt, max_tokens_override=1100)
            except Exception as e:
                app_logger.warning(f"[ZLintInterface] coverage judge LLM failed: {e}")
                continue
            obj = self._parse_judge_json(raw) or {}
            v = str(obj.get("verdict") or "none").lower()
            if v not in order:
                v = "none"
            reason = str(obj.get("reason") or obj.get("why") or "")[:600]
            fields = obj.get("fields") or {}
            lint = obj.get("lint")
            # deterministic wrong-field guard: downgrade full/partial when the rule
            # and the matched lint resolve to DIFFERENT specific subject families
            lint_subject = next((z.get("subject") for z in chunk if z.get("rule_id") == lint), None)
            v = self._consistent_verdict(v, lint, lint_subject, rule_fields.get("subject"))
            if order[v] > order[best["verdict"]] or (best["verdict"] == "none" and not best["reason"]):
                best = {"verdict": v, "lint": lint, "fields": fields,
                        "reason": reason, "n_cand": len(candidates)}
            if v == "full":
                break  # best possible; stop scanning further batches
        return best

    def is_zlint_available(self) -> bool:
        """Check if zlint is available"""
        return self.zlint_binary is not None

    def _get_all_existing_lints(self) -> Dict[str, Dict]:
        """
        Scan existing zlint files and extract all lint information
        Returns a dict mapping lint names to their metadata
        {
            "e_subject_common_name_max_length": {
                "name": "e_subject_common_name_max_length",
                "description": "...",
                "citation": "RFC 5280: A.1",
                "file_path": "..."
            },
            ...
        }
        """
        if self._existing_lints_cache is not None:
            return self._existing_lints_cache

        lints = {}
        lints_base = Path(self.zlint_lints_path)

        if not lints_base.exists():
            app_logger.warning(f"Lints directory not found: {lints_base}")
            self._existing_lints_cache = lints
            return lints

        # Scan all package directories (rfc, cabf_br, mozilla, etc.)
        for package_dir in lints_base.iterdir():
            if not package_dir.is_dir():
                continue

            # Read all .go files (excluding test files)
            for go_file in package_dir.glob('*.go'):
                # Skip test files
                if go_file.name.endswith('_test.go'):
                    continue

                try:
                    with open(go_file, 'r', encoding='utf-8') as f:
                        content = f.read()

                        # Extract Name field
                        name_match = re.search(r'Name:\s*"([^"]+)"', content)
                        if name_match:
                            name = name_match.group(1)

                            # Extract Description
                            desc_match = re.search(r'Description:\s*"([^"]+)"', content)
                            description = desc_match.group(1) if desc_match else ""

                            # Extract Citation
                            citation_match = re.search(r'Citation:\s*"([^"]+)"', content)
                            citation = citation_match.group(1) if citation_match else ""

                            lints[name] = {
                                "name": name,
                                "description": description,
                                "citation": citation,
                                "file_path": str(go_file),
                                "package": package_dir.name
                            }

                except Exception as e:
                    app_logger.warning(f"Error reading {go_file}: {e}")
                    continue

        app_logger.info(f"Scanned existing zlint files, found {len(lints)} lints")
        self._existing_lints_cache = lints
        return lints

    def _get_existing_lint_citations(self) -> Set[str]:
        """
        Scan existing zlint files and extract their Citations
        Returns a set of normalized citations (e.g., "RFC5280:4.2.1.9", "CABF_BR:7.1.2.1")
        """
        if self._existing_citations_cache is not None:
            return self._existing_citations_cache

        citations = set()
        lints_base = Path(self.zlint_lints_path)

        if not lints_base.exists():
            app_logger.warning(f"Lints directory not found: {lints_base}")
            self._existing_citations_cache = citations
            return citations

        # Scan all package directories (rfc, cabf_br, mozilla, etc.)
        for package_dir in lints_base.iterdir():
            if not package_dir.is_dir():
                continue

            # Read all .go files (excluding test files and our generated ones)
            for go_file in package_dir.glob('*.go'):
                # Skip test files
                if go_file.name.endswith('_test.go'):
                    continue

                # Skip our previously generated files (pattern: lint_rfc_X_Y_Z_certificate.go)
                if re.match(r'lint_\w+_\d+.*_certificate\.go$', go_file.name):
                    continue

                try:
                    with open(go_file, 'r', encoding='utf-8') as f:
                        content = f.read()

                        # Extract Citation from the init() function
                        # Pattern: Citation: "RFC 5280: 4.2.1.9" or Citation: "BRs: 7.1.2.1"
                        citation_match = re.search(r'Citation:\s*"([^"]+)"', content)
                        if citation_match:
                            citation = citation_match.group(1)
                            # Normalize: "RFC 5280: 4.2.1.9" -> "RFC5280:4.2.1.9"
                            normalized = re.sub(r'\s+', '', citation).upper()
                            citations.add(normalized)
                            app_logger.debug(f"Found citation in {go_file.name}: {citation} -> {normalized}")

                except Exception as e:
                    app_logger.warning(f"Error reading {go_file}: {e}")
                    continue

        app_logger.info(f"Scanned existing zlint files, found {len(citations)} unique citations")
        self._existing_citations_cache = citations
        return citations

    def _normalize_rule_citation(self, rule: Dict) -> str:
        """
        Normalize a rule's citation for comparison
        Returns format like "RFC5280:4.2.1.9" or "CABF_BR:7.1.2.1"
        """
        source = (rule.get('source') or 'RFC').upper().strip()
        section = (rule.get('section') or '').strip()

        if not section:
            return ""

        # Handle different source formats
        if source in ['RFC', 'RFC5280', 'RFC2459']:
            source = 'RFC5280'
        elif source in ['CABF', 'CABF_BR', 'BRS']:
            source = 'CABF_BR'

        # Normalize: remove all spaces
        return f"{source}:{section}".replace(' ', '')

    async def check_rule_coverage_intelligent(self, rule: Dict, candidate_lints: Optional[List[Dict]] = None) -> Dict:
        """判断一条规则的 IR 是否已被某个 zlint 检查实现（覆盖判别）。

        方法（按 source 缩小候选 + 字段级 LLM 判别）：
        - 候选：默认 RFC 规则 → RFC lint 按章节匹配（章节稳定）；CABF-BR 规则 → 全部
          CABF-BR lint（章节漂移）。调用方可传 candidate_lints 覆盖默认候选——CABF
          全集 170 条全量比对易在拥挤批次里误判 full，driver 用 bge-m3 embedding
          top-k 预筛后传入（更准更快；配合 _consistent_verdict 守卫）。
        - 判别：把规则 IR 的 subject/obligation/predicate/constraint/precondition 与
          候选 lint 的同名 IR 字段逐字段比对，给 full / partial / none 三档判决。
        - 覆盖 = full（已实现，跳过代码生成）；partial/none = 仍需生成。
        - 无论匹配与否都返回具体的字段级理由（none 时点名最接近的 lint 并说明差异）。

        Args:
            rule: {text, source, section, ir|ir_data}（IR 用于字段级比对，强烈建议传入）
            candidate_lints: 可选，预筛好的 zlint lint IR 候选列表（embedding top-k）。
                             传入则直接用它做候选，跳过按 source/section 的默认选取。

        Returns:
            {has_coverage, verdict, lint_name, needs_generation, match_method,
             matched_lints, reasoning, fields, n_candidates}
        """
        if not self._coverage_initialized:
            app_logger.warning("[ZLintInterface] Coverage detection not initialized; initializing now.")
            await self.initialize_coverage_detection()

        rule_source = rule.get('source')
        rule_section = rule.get('section')
        if not rule_source:
            return {
                'has_coverage': False, 'verdict': 'none', 'lint_name': None,
                'needs_generation': True, 'match_method': 'no_source',
                'matched_lints': [], 'fields': {}, 'n_candidates': 0,
                'reasoning': 'Rule missing source field; cannot scope zlint candidates.',
            }

        candidates = (candidate_lints if candidate_lints is not None
                      else self._coverage_candidates(rule_source, rule_section))
        rule_fields = self._rule_ir_fields(rule)
        verdict_obj = await self._judge_coverage(rule_fields, candidates)

        verdict = verdict_obj['verdict']
        covered = (verdict == 'full')
        lint_name = verdict_obj.get('lint')
        matched = []
        if covered and lint_name:
            matched = [{'lint_name': lint_name, 'verdict': verdict,
                        'fields': verdict_obj.get('fields') or {}}]
        app_logger.info(
            f"[ZLintInterface] coverage {rule_source}:{rule_section} -> {verdict} "
            f"(lint={lint_name}, n_cand={verdict_obj.get('n_cand')})"
        )
        return {
            'has_coverage': covered,
            'verdict': verdict,                       # full | partial | none
            'lint_name': lint_name if covered else None,
            'needs_generation': not covered,          # full=skip codegen; partial/none=generate
            'match_method': 'llm_field_coverage',
            'matched_lints': matched,
            'fields': verdict_obj.get('fields') or {},
            'n_candidates': verdict_obj.get('n_cand', len(candidates)),
            'reasoning': verdict_obj.get('reason') or '',   # detailed field-level reason (always present)
        }

    def generate_and_install_lint(self, rule: Dict) -> Dict:
        """
        Generate zlint code for rule and install it

        Args:
            rule: Rule dictionary

        Returns:
            {
                'success': bool,
                'file_path': str,
                'compile_success': bool,
                'error': str or None
            }
        """
        try:
            app_logger.info(f"Generating zlint code for rule: {rule.get('text', '')[:50]}")

            # Generate lint file
            file_path = self.generator.save_lint_file(rule)

            # Try to compile zlint
            compile_result = self._compile_zlint()

            return {
                'success': True,
                'file_path': file_path,
                'compile_success': compile_result['success'],
                'error': None if compile_result['success'] else 'Compilation warning (lint may still work)'
            }

        except Exception as e:
            app_logger.error(f"Failed to generate lint: {e}")
            return {
                'success': False,
                'file_path': None,
                'compile_success': False,
                'error': str(e)
            }

    def save_generated_code(self, lint_name: str, package_name: str, go_code: str, file_path: str = None) -> Dict:
        """
        Save generated Go code to zlint project

        Args:
            lint_name: Name of the lint
            package_name: Package name (e.g., 'rfc', 'cabf_br')
            go_code: Generated Go code
            file_path: Optional custom file path (default: auto-generate based on package)

        Returns:
            {
                'success': bool,
                'file_path': str,
                'error': str or None
            }
        """
        try:
            # Determine output file path
            if file_path:
                output_file = Path(file_path)
            else:
                # Package directory should already exist in zlint project
                lints_dir = Path(self.zlint_lints_path) / package_name
                output_file = lints_dir / f"lint_{lint_name.lower()}.go"

                # Verify package directory exists
                if not lints_dir.exists():
                    raise FileNotFoundError(f"Package directory not found: {lints_dir}. Please check zlint_path configuration.")

            # Write code to file
            with open(output_file, 'w') as f:
                f.write(go_code)

            app_logger.info(f"Saved generated code to: {output_file}")

            return {
                'success': True,
                'file_path': str(output_file),
                'error': None
            }

        except Exception as e:
            app_logger.error(f"Failed to save generated code: {e}")
            return {
                'success': False,
                'file_path': None,
                'error': str(e)
            }

    def _compile_zlint(self) -> dict:
        """
        Compile zlint after adding new lints

        编译后的二进制保存到zlint根目录，便于后续验证使用

        Returns:
            dict with keys:
                - success: bool
                - stdout: str (compilation output)
                - stderr: str (error output)
                - returncode: int
                - binary_path: str (path to compiled binary)
        """
        zlint_v3_path = Path(self.zlint_path) / 'v3'

        if not os.path.exists(zlint_v3_path):
            app_logger.warning(f"zlint v3 path not found: {zlint_v3_path}")
            return {
                'success': False,
                'stdout': '',
                'stderr': f'zlint v3 path not found: {zlint_v3_path}',
                'returncode': -1,
                'binary_path': None
            }

        # 输出到 zlint/v3/zlint/zlint（与 _find_zlint_binary 一致）
        import platform
        binary_name = 'zlint.exe' if platform.system() == 'Windows' else 'zlint'
        output_binary = zlint_v3_path / binary_name

        try:
            app_logger.info(f"Starting zlint compilation in {zlint_v3_path}...")

            # Run go build with default output (zlint/v3/zlint)
            # Set GOTOOLCHAIN=local to use installed Go version
            env = os.environ.copy()
            env['GOTOOLCHAIN'] = 'local'

            result = subprocess.run(
                ['go', 'build', './cmd/zlint'],
                cwd=str(zlint_v3_path),
                capture_output=True,
                text=True,
                timeout=180,  # 增加到3分钟
                env=env
            )

            success = result.returncode == 0

            if success:
                app_logger.info(f"✅ zlint compiled successfully: {output_binary}")
                # 更新zlint_binary路径
                self.zlint_binary = str(output_binary)
            else:
                app_logger.warning(f"zlint compilation failed with code {result.returncode}")

            return {
                'success': success,
                'stdout': result.stdout,
                'stderr': result.stderr,
                'returncode': result.returncode,
                'binary_path': str(output_binary) if success else None
            }

        except subprocess.TimeoutExpired:
            error_msg = "Compilation timeout after 180 seconds"
            app_logger.error(error_msg)
            return {
                'success': False,
                'stdout': '',
                'stderr': error_msg,
                'returncode': -1,
                'binary_path': None
            }
        except Exception as e:
            error_msg = f"Failed to compile zlint: {str(e)}"
            app_logger.error(error_msg)
            return {
                'success': False,
                'stdout': '',
                'stderr': error_msg,
                'returncode': -1,
                'binary_path': None
            }

    def validate_certificate(self, cert_pem: str) -> Dict:
        """
        Validate certificate using zlint

        Args:
            cert_pem: PEM encoded certificate

        Returns:
            {
                'success': bool,
                'results': List[Dict],  # List of lint results
                'errors': List[str],
                'warnings': List[str],
                'total_lints': int,
                'error_count': int,
                'warning_count': int
            }
        """
        if not self.is_zlint_available():
            app_logger.error("zlint binary not available")
            return {
                'success': False,
                'is_compliant': False,
                'errors': [
                    'zlint验证工具不可用。这是系统配置问题，无法执行证书验证。'
                    '可能原因：1) zlint未正确安装 2) zlint可执行文件路径配置错误 3) 文件权限问题。'
                    '请联系系统管理员安装或配置zlint工具。'
                ],
                'warnings': [],
                'results': [],
                'total_lints': 0,
                'error_count': 1,
                'warning_count': 0,
                'error': 'zlint binary not available - please check zlint installation'
            }

        try:
            # 【调试】记录证书的前100个字符
            cert_preview = cert_pem[:100] if len(cert_pem) > 100 else cert_pem
            app_logger.info(f"📄 Certificate PEM (first 100 chars): {repr(cert_preview)}")
            app_logger.info(f"📄 Certificate PEM length: {len(cert_pem)} chars")

            # 【详细的PEM格式检查】
            cert_pem_stripped = cert_pem.strip()

            # 检查1: 必须以BEGIN CERTIFICATE开头
            if not cert_pem_stripped.startswith('-----BEGIN CERTIFICATE-----'):
                app_logger.error(f"❌ Invalid PEM format: does not start with '-----BEGIN CERTIFICATE-----'")
                app_logger.error(f"   First 50 chars: {repr(cert_pem_stripped[:50])}")

                # 尝试诊断问题
                if cert_pem_stripped.startswith('-----BEGIN'):
                    match_type = cert_pem_stripped.split('-----')[1].strip()
                    error_detail = f'PEM文件类型错误：找到 "{match_type}"，但需要 "BEGIN CERTIFICATE"'
                else:
                    error_detail = 'PEM文件缺少 "-----BEGIN CERTIFICATE-----" 标记'

                return {
                    'success': False,
                    'is_compliant': False,
                    'errors': [f'{error_detail}。请确保上传的是有效的X.509证书PEM文件。'],
                    'warnings': [],
                    'results': [],
                    'total_lints': 0,
                    'error_count': 1,
                    'warning_count': 0,
                    'error': error_detail
                }

            # 检查2: 必须以END CERTIFICATE结尾
            if not cert_pem_stripped.endswith('-----END CERTIFICATE-----'):
                app_logger.error(f"❌ Invalid PEM format: does not end with '-----END CERTIFICATE-----'")
                app_logger.error(f"   Last 50 chars: {repr(cert_pem_stripped[-50:])}")

                error_detail = 'PEM文件缺少 "-----END CERTIFICATE-----" 标记或被截断'
                return {
                    'success': False,
                    'is_compliant': False,
                    'errors': [f'{error_detail}。证书内容可能不完整，请检查是否完整复制了证书内容。'],
                    'warnings': [],
                    'results': [],
                    'total_lints': 0,
                    'error_count': 1,
                    'warning_count': 0,
                    'error': error_detail
                }

            # 检查3: 检查PEM内容是否包含非法字符
            import re
            lines = cert_pem_stripped.split('\n')
            base64_lines = [line for line in lines if not line.startswith('-----')]

            for i, line in enumerate(base64_lines):
                # Base64只应包含: A-Z, a-z, 0-9, +, /, =
                if not re.match(r'^[A-Za-z0-9+/=]*$', line):
                    illegal_chars = [c for c in line if c not in 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=']
                    app_logger.error(f"❌ Invalid PEM content: line {i+2} contains illegal characters: {illegal_chars}")

                    error_detail = f'PEM文件第{i+2}行包含非法字符 {illegal_chars}。Base64编码只能包含字母、数字、+、/ 和 ='
                    return {
                        'success': False,
                        'is_compliant': False,
                        'errors': [f'{error_detail}。可能原因：1) 复制粘贴时引入了特殊字符 2) 文件编码问题 3) 内容被损坏。建议重新导出证书。'],
                        'warnings': [],
                        'results': [],
                        'total_lints': 0,
                        'error_count': 1,
                        'warning_count': 0,
                        'error': error_detail
                    }

            # 检查4: 检查是否有多个证书（证书链）
            begin_count = cert_pem.count('-----BEGIN CERTIFICATE-----')
            if begin_count > 1:
                app_logger.warning(f"⚠️ PEM contains {begin_count} certificates (certificate chain)")
                # 只使用第一个证书
                first_begin = cert_pem.index('-----BEGIN CERTIFICATE-----')
                first_end = cert_pem.index('-----END CERTIFICATE-----', first_begin) + len('-----END CERTIFICATE-----')
                cert_pem_clean = cert_pem[first_begin:first_end].strip()
                app_logger.info(f"📝 Extracted first certificate from chain ({len(cert_pem_clean)} chars)")
            else:
                cert_pem_clean = cert_pem_stripped

            # Write certificate to temporary file (use text mode with UTF-8 encoding and Unix line endings)
            with tempfile.NamedTemporaryFile(mode='w', suffix='.pem', delete=False, encoding='utf-8', newline='\n') as f:
                f.write(cert_pem_clean)
                f.write('\n')  # Ensure file ends with newline
                temp_file = f.name

            app_logger.info(f"📝 Written certificate to temp file: {temp_file} ({len(cert_pem_clean)} chars)")

            try:
                # Run zlint
                app_logger.info(f"🔧 Calling zlint binary: {self.zlint_binary} -pretty {temp_file}")
                result = subprocess.run(
                    [self.zlint_binary, '-pretty', temp_file],
                    capture_output=True,
                    text=True,
                    timeout=30
                )

                app_logger.info(f"[OK] zlint executed with return code: {result.returncode}")
                app_logger.debug(f"zlint stdout length: {len(result.stdout)} bytes")

                # Parse output
                if result.returncode == 0:
                    output = self._parse_zlint_output(result.stdout)
                    app_logger.info(f"[OK] zlint found {output.get('total_lints', 0)} lints, "
                                  f"{output.get('error_count', 0)} errors, "
                                  f"{output.get('warning_count', 0)} warnings")
                    return output
                else:
                    # zlint执行失败，分析stderr提供详细诊断
                    stderr = result.stderr.strip()
                    app_logger.error(f"[X] zlint failed with return code {result.returncode}")
                    app_logger.error(f"[X] zlint stderr: {stderr}")

                    # 分析常见错误并提供详细建议
                    error_detail = None
                    suggestions = []

                    if 'unable to parse PEM' in stderr.lower():
                        error_detail = 'zlint无法解析PEM格式的证书文件'
                        suggestions = [
                            '证书PEM格式可能存在问题',
                            '请检查：1) 是否包含完整的 BEGIN/END 标记',
                            '2) Base64编码内容是否包含非法字符',
                            '3) 是否有隐藏的控制字符或编码问题',
                            '4) 建议使用 openssl x509 -in cert.pem -text -noout 命令验证证书是否有效'
                        ]
                    elif 'invalid format' in stderr.lower():
                        error_detail = 'zlint检测到证书格式无效'
                        suggestions = [
                            '证书可能不是标准的X.509格式',
                            '请确认上传的是证书文件而不是其他类型的文件（如私钥、CSR等）'
                        ]
                    elif 'no such file' in stderr.lower() or 'cannot find' in stderr.lower():
                        error_detail = 'zlint无法找到临时文件'
                        suggestions = [
                            '这是系统内部错误，可能是临时目录权限问题',
                            '请联系系统管理员'
                        ]
                    else:
                        error_detail = f'zlint验证失败（返回码 {result.returncode}）'
                        suggestions = [
                            f'原始错误信息：{stderr}',
                            '这可能是证书格式问题或zlint内部错误',
                            '建议使用标准工具（如openssl）验证证书是否有效'
                        ]

                    # 构建错误消息
                    error_message = f"{error_detail}。{' '.join(suggestions)}"

                    return {
                        'success': False,
                        'is_compliant': False,
                        'errors': [error_message],
                        'warnings': [],
                        'results': [],
                        'total_lints': 0,
                        'error_count': 1,
                        'warning_count': 0,
                        'error': error_detail,
                        'raw_stderr': stderr  # 保留原始错误信息供调试
                    }

            finally:
                # Clean up temp file
                os.unlink(temp_file)

        except subprocess.TimeoutExpired:
            app_logger.error("zlint execution timeout after 30 seconds")
            return {
                'success': False,
                'is_compliant': False,
                'errors': [
                    'zlint验证超时（30秒）。可能原因：1) 证书过大或格式复杂 2) 系统资源不足 3) zlint进程卡死。'
                    '建议：1) 检查证书大小是否合理 2) 重试验证 3) 如持续超时请联系管理员'
                ],
                'warnings': [],
                'results': [],
                'total_lints': 0,
                'error_count': 1,
                'warning_count': 0,
                'error': 'zlint validation timeout (30s)'
            }
        except Exception as e:
            app_logger.error(f"zlint validation error: {e}", exc_info=True)

            # 分析异常类型提供更详细的信息
            error_type = type(e).__name__
            error_msg = str(e)

            if 'Permission' in error_type or 'permission' in error_msg.lower():
                error_detail = '权限错误：无法创建临时文件或执行zlint'
                suggestions = '请检查：1) 临时目录权限 2) zlint可执行文件权限 3) 联系系统管理员'
            elif 'FileNotFound' in error_type or 'not found' in error_msg.lower():
                error_detail = '文件未找到：zlint可执行文件或临时文件丢失'
                suggestions = '这是系统配置问题，请联系管理员检查zlint安装路径'
            elif 'Encoding' in error_type or 'encoding' in error_msg.lower():
                error_detail = '编码错误：证书内容包含无效字符'
                suggestions = '请检查：1) 证书文件编码是否为UTF-8 2) 是否包含特殊字符 3) 重新导出证书'
            else:
                error_detail = f'系统错误：{error_type}'
                suggestions = f'错误详情：{error_msg}。这可能是系统内部错误，请联系管理员并提供此错误信息'

            return {
                'success': False,
                'is_compliant': False,
                'errors': [f'{error_detail}。{suggestions}'],
                'warnings': [],
                'results': [],
                'total_lints': 0,
                'error_count': 1,
                'warning_count': 0,
                'error': f'{error_detail}: {error_msg}',
                'exception_type': error_type
            }

    def _parse_zlint_output(self, output: str) -> Dict:
        """Parse zlint JSON output"""
        try:
            data = json.loads(output)

            results = []
            errors = []
            warnings = []

            # Parse lints results
            for lint_name, result in data.items():
                if lint_name in ['version', 'timestamp']:
                    continue

                result_dict = {
                    'lint_name': lint_name,
                    'result': result.get('result', 'unknown'),
                    'details': result.get('details', '')
                }

                results.append(result_dict)

                if result.get('result') == 'error':
                    errors.append(f"{lint_name}: {result.get('details', 'Error')}")
                elif result.get('result') == 'warn':
                    warnings.append(f"{lint_name}: {result.get('details', 'Warning')}")

            # 记录详细的zlint结果（在return之前）
            app_logger.info(f"✅ Zlint validation complete: errors={len(errors)}, warnings={len(warnings)}, is_compliant={len(errors) == 0}")

            # 【调试】详细记录每个error和warning
            if errors:
                app_logger.info(f"  Errors found: {errors}")
            if warnings:
                app_logger.info(f"  Warnings found: {warnings}")

            return {
                'success': True,
                'results': results,
                'errors': errors,
                'warnings': warnings,
                'total_lints': len(results),
                'error_count': len(errors),
                'warning_count': len(warnings),
                'is_compliant': len(errors) == 0
            }

        except json.JSONDecodeError:
            # Try plain text parsing
            lines = output.strip().split('\n')
            errors = [line for line in lines if 'error' in line.lower()]
            warnings = [line for line in lines if 'warn' in line.lower()]

            return {
                'success': True,
                'results': [{'lint_name': 'parsed_text', 'result': output}],
                'errors': errors,
                'warnings': warnings,
                'total_lints': 1,
                'error_count': len(errors),
                'warning_count': len(warnings),
                'is_compliant': len(errors) == 0
            }

    async def validate_with_specific_rules(self, cert_pem: str, rules: List[Dict]) -> Dict:
        """
        Validate certificate with specific rules

        Args:
            cert_pem: PEM encoded certificate
            rules: List of rules to check

        Returns:
            Validation results with per-rule details
        """
        # Check coverage for each rule (V2: three-layer validation)
        coverage_status = []
        needs_generation = []

        for rule in rules:
            coverage = await self.check_rule_coverage_intelligent(rule)
            coverage_status.append({
                'rule': rule,
                'coverage': coverage
            })

            if coverage['needs_generation']:
                needs_generation.append(rule)

        # Generate missing lints
        generated = []
        if needs_generation:
            app_logger.info(f"Generating {len(needs_generation)} missing lints...")
            for rule in needs_generation:
                gen_result = self.generate_and_install_lint(rule)
                generated.append({
                    'rule': rule,
                    'result': gen_result
                })

        # Run validation
        validation_result = self.validate_certificate(cert_pem)

        return {
            'validation': validation_result,
            'coverage_status': coverage_status,
            'generated_lints': generated,
            'total_rules': len(rules),
            'covered_rules': len([c for c in coverage_status if c['coverage']['has_coverage']]),
            'generated_count': len(generated)
        }

    def get_lint_source_code(self, lint_name: str) -> Optional[str]:
        """
        获取指定zlint的Go源码

        Args:
            lint_name: lint名称，如 "e_subject_common_name_max_length"

        Returns:
            Go源码字符串，如果找不到则返回None
        """
        # 从缓存中获取lint信息
        all_lints = self._get_all_existing_lints()

        if lint_name not in all_lints:
            app_logger.warning(f"Lint '{lint_name}' not found in cache")
            return None

        lint_info = all_lints[lint_name]
        file_path = lint_info.get('file_path')

        if not file_path or not os.path.exists(file_path):
            app_logger.warning(f"Source file not found for lint '{lint_name}': {file_path}")
            return None

        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                source_code = f.read()

            app_logger.debug(f"Retrieved source code for '{lint_name}' ({len(source_code)} bytes)")
            return source_code

        except Exception as e:
            app_logger.error(f"Error reading source code for '{lint_name}': {e}")
            return None

    def get_lint_info_with_source(self, lint_name: str) -> Dict:
        """
        获取lint的详细信息（包含源码）

        Args:
            lint_name: lint名称

        Returns:
            {
                'name': str,
                'description': str,
                'citation': str,
                'package': str,
                'file_path': str,
                'source_code': str  # Go源码
            }
        """
        # 获取基础信息
        all_lints = self._get_all_existing_lints()

        if lint_name not in all_lints:
            return {
                'error': f"Lint '{lint_name}' not found",
                'name': lint_name
            }

        lint_info = all_lints[lint_name].copy()

        # 添加源码
        source_code = self.get_lint_source_code(lint_name)
        lint_info['source_code'] = source_code

        return lint_info
