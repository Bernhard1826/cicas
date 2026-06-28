"""Label-don't-drop merge for the extraction pipeline.

Layer 1 (RuleDiscovery) is the full-recall set: one skeleton per RFC2119
assertion ("宁可误报，不可漏报"). Layer 2 (LLM) then drops skeletons it can't turn
into an IR (no `.ir`, override aggregation, scope filter) — those sentences
never reach the DB and become un-auditable, breaking the Q1 conservation check.

This module reconciles the two: every skeleton must be represented in the
persisted set. Skeletons whose IR survived keep the rich IR rule_dict; skeletons
with no surviving IR get a minimal *labeled* rule_dict (extraction_method=
'regex_unclassified') instead of being dropped. The later classification stage
labels them noise / non-executable / executable.

Join is by (normalized text, normalized keyword): the LLM context does NOT carry
the skeleton's sentence_index or rule_id (see context_builder._build_base_context),
so sentence_index/rule_id cannot be relied on to map an IR back to its skeleton.
The keyword is part of the key so that a multi-keyword sentence whose MUST IR
survived still re-emits its MAY assertion as a labeled row. Ambiguity resolves
toward recall (an unmatched skeleton is re-emitted, never silently dropped).
"""
from __future__ import annotations
import re
import hashlib
from typing import List, Dict, Any

_NONALNUM = re.compile(r'[^a-z0-9 ]')
_WS = re.compile(r'\s+')


def _norm_text(s: str) -> str:
    return _WS.sub(' ', _NONALNUM.sub(' ', (s or '').lower())).strip()


# Map IR obligation forms back to RFC2119 keyword forms used by skeletons.
_KW_CANON = {
    'must': 'MUST', 'required': 'MUST', 'shall': 'MUST',
    'must not': 'MUST NOT', 'shall not': 'MUST NOT',
    'prohibition': 'MUST NOT', 'prohibited': 'MUST NOT',
    'should': 'SHOULD', 'recommended': 'SHOULD',
    'should not': 'SHOULD NOT', 'not recommended': 'SHOULD NOT',
    'may': 'MAY', 'optional': 'MAY', 'permission': 'MAY', 'permitted': 'MAY',
}


def _norm_kw(k) -> str:
    if not k:
        return ''
    s = _WS.sub(' ', re.sub(r'[_\-]', ' ', str(k).strip().lower()))
    return _KW_CANON.get(s, s.upper())


def merge_label_dont_drop(skeletons: List[Any], layer2_rules: List[Dict[str, Any]],
                          logger=None) -> List[Dict[str, Any]]:
    """Return layer2_rules plus a labeled fallback row for every skeleton that
    Layer 2 dropped. Pure / deterministic — safe to unit-test offline.

    Also backfills sentence_index onto surviving IR rows: the LLM context drops
    the skeleton's sentence_index (see context_builder._build_base_context), so a
    surviving IR arrives with sentence_index=None. The DB dedup key includes
    sentence_index, so leaving it None collapses distinct same-(text,section,kw)
    assertions into one row and silently destroys recall (RFC5280: 596→386). We
    recover it from the matching skeleton via the same (text,kw,section) join used
    for the label-don't-drop fallback; ambiguity resolves to the first skeleton at
    that key (keyword_position 0), which is recall-safe."""
    # 去重键含 section：跨章节同措辞是不同扩展的独立规则，须各自落库（label-don't-drop）
    # skeleton_index: (text,kw,section) -> sentence_index, to backfill onto IR rows.
    skeleton_index: Dict[Any, int] = {}
    for sk in skeletons:
        k = (_norm_text(getattr(sk, 'sentence', '')),
             _norm_kw(getattr(sk, 'keyword', '')),
             (getattr(sk, 'section', '') or '').strip())
        sidx = getattr(sk, 'sentence_index', None)
        if sidx is not None and k not in skeleton_index:
            skeleton_index[k] = sidx

    covered = set()
    for r in layer2_rules:
        k = (_norm_text(r.get('text')),
             _norm_kw(r.get('requirement_level') or r.get('rule_type')),
             (r.get('section') or '').strip())
        covered.add(k)
        # Backfill position so the DB dedup key keeps distinct assertions distinct.
        if r.get('sentence_index') is None and k in skeleton_index:
            r['sentence_index'] = skeleton_index[k]

    out = list(layer2_rules)
    added = 0
    for sk in skeletons:
        text = getattr(sk, 'sentence', '') or ''
        kw = getattr(sk, 'keyword', '') or ''
        nt = _norm_text(text)
        if len(nt) < 3:
            continue
        key = (nt, _norm_kw(kw), (getattr(sk, 'section', '') or '').strip())
        if key in covered:
            continue
        covered.add(key)  # dedups identical assertions within the same section only
        out.append({
            'text': text,
            'section': getattr(sk, 'section', '') or '',
            'title': getattr(sk, 'section_title', '') or '',
            'requirement_level': kw,
            'rule_type': kw,
            'modality': kw,
            'sentence_index': getattr(sk, 'sentence_index', None),
            'sentence_hash': hashlib.md5(text.encode('utf-8')).hexdigest(),
            'extraction_method': 'regex_unclassified',
            'keyword_source': getattr(sk, 'keyword_source', 'direct'),
            'parent_rule_id': getattr(sk, 'parent_rule_id', None),
            'unclassified': True,
        })
        added += 1

    if logger is not None:
        logger.info(
            f"[label-don't-drop] skeletons={len(skeletons)} "
            f"layer2_rules={len(layer2_rules)} labeled_added={added} final={len(out)}"
        )
    return out
