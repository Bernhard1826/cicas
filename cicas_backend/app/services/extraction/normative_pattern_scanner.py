"""
Normative Pattern Scanner

Detects normative/definitional statements that do NOT contain explicit RFC2119
keywords (MUST/SHALL/SHOULD/MAY) but still express normative requirements.

Examples from RFC 5280 §7.2:
- "IA5String is limited to the set of ASCII characters"
  → definitional constraint, no explicit keyword
- "a])] is considered to fall within the subtree"
  → definitional/semantic rule, no explicit keyword
- "is equivalent to a dNSName"
  → equivalence definition

These patterns complement the existing RFC2119 keyword-based rule discovery
to improve recall for rules that use definitional language.
"""
import re
from typing import List, Optional, Tuple
from dataclasses import dataclass
from app.core.logging_config import app_logger


@dataclass
class NormativeMatch:
    """
    A normative statement detected without RFC2119 keywords.

    Represents a sentence/clause that expresses a normative requirement
    through definitional or semantic patterns rather than explicit keywords.
    """
    sentence: str                           # Full matched sentence
    pattern_type: str                       # Type of pattern matched (see NORMATIVE_PATTERNS)
    matched_phrase: str                     # The specific phrase that triggered the match
    match_position: int                     # Position in sentence where pattern was found
    section: Optional[str] = None           # Section ID if available
    sentence_index: Optional[int] = None    # Sentence index in document

    # Context
    paragraph_text: Optional[str] = None
    section_title: Optional[str] = None


class NormativePatternScanner:
    """
    Detect normative statements without RFC2119 keywords.

    This scanner finds sentences that express requirements through
    definitional or semantic patterns rather than explicit RFC2119 keywords.
    """

    # Normative patterns: (regex, pattern_type, description)
    # Each pattern captures text that expresses a normative/definitional rule
    # without using MUST/SHALL/SHOULD/MAY.
    NORMATIVE_PATTERNS: List[Tuple[str, str, str]] = [
        # NOTE(2026-06-10): 删除了两个把"描述句"误当规范的 pattern——
        #   definitional "is considered to be/fall/have"  和
        #   specification "X specifies/defines/designates Y"。
        # "X defines/specifies Y" 是在陈述 X 是什么(描述/定义),不是要求
        # (会发生什么), 召回它们等于把 §4.2.x 扩展定义散文当规则(经审计:
        # specification 误召 28、definitional 误召 4)。真正的规范定义句会带
        # RFC2119 关键词, 由 Layer1 捕获; 无关键词的纯描述句不应作为规则召回。

        # Equivalence patterns: "X is equivalent/identical/equal to Y"
        (r'is\s+(?:equivalent|identical|equal)\s+to\b',
         'equivalence', 'Equivalence definition'),

        # Constraint patterns: "X is limited/restricted/confined to Y"
        (r'is\s+(?:limited|restricted|confined)\s+to\b',
         'constraint', 'Constraint definition'),

        # Requirement patterns (passive): "X is required/expected/needed to Y"
        (r'is\s+(?:required|expected|needed)\s+to\b',
         'requirement', 'Passive requirement'),

        # Delegation patterns (ETSI-style) — tightened to require a standard/RFC reference
        # to avoid false positives from generic "in accordance with industry practice" etc.
        (r'\b(?:shall|must|should)\s+comply\s+with\b',
         'delegation', 'Delegation: "shall comply with"'),

        # "in accordance with" only when followed by a spec reference (RFC/ETSI/ISO/CABF/clause)
        (r'\bin\s+accordance\s+with\s+(?:the\s+)?(?:requirements?\s+of\s+)?'
         r'(?:RFC|ETSI|ISO|IEC|IETF|CA/B\s*Forum|CABF|clause|section|annex|\[)\b',
         'delegation', 'Delegation: "in accordance with [spec]"'),

        # "as specified/defined in" only when followed by RFC/ETSI/a section reference
        (r'\bas\s+(?:specified|defined|required|stated|described)\s+in\s+'
         r'(?:RFC|ETSI|ISO|IEC|IETF|Section|Clause|Annex|\[)\b',
         'delegation', 'Delegation: "as specified in [spec]"'),

        # "conform(s) to" only before a spec name
        (r'\bconform(?:s)?\s+to\s+(?:the\s+)?(?:requirements?\s+(?:of|in)\s+)?'
         r'(?:RFC|ETSI|ISO|IEC|IETF|CABF|this\s+(?:document|standard|profile))\b',
         'delegation', 'Delegation: "conform(s) to [spec]"'),

        (r'\bsubject\s+to\s+(?:the\s+)?(?:requirements?|constraints?|rules?)\s+(?:of|in)\b',
         'delegation', 'Delegation: "subject to the requirements of"'),

        # Prohibition patterns: "X is not permitted/allowed/valid"
        (r'is\s+not\s+(?:permitted|allowed|valid|acceptable)\b',
         'prohibition', 'Prohibition without keyword'),

        # Inclusion requirement: "X is to include/contain/have"
        (r'is\s+to\s+(?:include|contain|have|be)\b',
         'inclusion', 'Inclusion requirement'),

        # Conditional definition: "X matches/satisfies Y if/when/only"
        (r'(?:matches|satisfies|meets)\s+(?:the\s+)?(?:requirements?|criteria|conditions?)\b',
         'conditional_match', 'Conditional match definition'),

        # (removed 2026-06-10) 'specification' pattern "X specifies/defines/
        # designates Y" — pure descriptive, not normative; see note at top.
    ]

    # RFC2119 keywords to exclude (we only want non-keyword sentences)
    RFC2119_KEYWORDS_PATTERN = re.compile(
        r'\b(?:MUST(?:\s+NOT)?|SHALL(?:\s+NOT)?|SHOULD(?:\s+NOT)?|'
        r'MAY|REQUIRED|RECOMMENDED|OPTIONAL)\b'
    )

    def __init__(self):
        """Initialize the scanner with compiled patterns."""
        self.compiled_patterns = [
            (re.compile(pattern, re.IGNORECASE), ptype, desc)
            for pattern, ptype, desc in self.NORMATIVE_PATTERNS
        ]

        app_logger.info(
            f"[NormativePatternScanner] Initialized with {len(self.compiled_patterns)} patterns"
        )

    def scan(
        self,
        section_text: str,
        section_id: Optional[str] = None,
        section_title: Optional[str] = None,
        base_sentence_index: int = 0
    ) -> List[NormativeMatch]:
        """
        Scan text for normative statements without RFC2119 keywords.

        Args:
            section_text: Text to scan
            section_id: Section identifier for provenance
            section_title: Section title for context
            base_sentence_index: Starting sentence index for this section

        Returns:
            List of NormativeMatch objects
        """
        matches = []

        # Split into sentences
        sentences = self._split_sentences(section_text)

        for sent_idx, sentence in enumerate(sentences):
            sentence = sentence.strip()
            if not sentence or len(sentence) < 15:
                continue

            # Skip sentences that already have RFC2119 keywords
            # (those are handled by the regular RuleDiscovery)
            if self.RFC2119_KEYWORDS_PATTERN.search(sentence):
                continue

            # Check each normative pattern
            for compiled_pattern, pattern_type, description in self.compiled_patterns:
                match = compiled_pattern.search(sentence)
                if match:
                    normative_match = NormativeMatch(
                        sentence=sentence,
                        pattern_type=pattern_type,
                        matched_phrase=match.group(0),
                        match_position=match.start(),
                        section=section_id,
                        sentence_index=base_sentence_index + sent_idx,
                        paragraph_text=section_text[:500] if section_text else None,
                        section_title=section_title
                    )
                    matches.append(normative_match)

                    app_logger.debug(
                        f"[NormativePatternScanner] Found '{pattern_type}' pattern: "
                        f"'{sentence[:60]}...' (section {section_id})"
                    )

                    # Only match first pattern per sentence
                    break

        if matches:
            app_logger.info(
                f"[NormativePatternScanner] Found {len(matches)} normative patterns "
                f"in section {section_id}"
            )

        return matches

    def scan_document(
        self,
        document_text: str,
        sections: Optional[List[dict]] = None
    ) -> List[NormativeMatch]:
        """
        Scan an entire document for normative patterns.

        Args:
            document_text: Full document text
            sections: Pre-parsed sections (optional). If not provided,
                      the entire text is scanned as one section.
                      Each dict should have: section_id, title, text

        Returns:
            List of all NormativeMatch objects found
        """
        all_matches = []
        sentence_index = 0

        if sections:
            for section in sections:
                section_matches = self.scan(
                    section_text=section.get('text', ''),
                    section_id=section.get('section_id'),
                    section_title=section.get('title'),
                    base_sentence_index=sentence_index
                )
                all_matches.extend(section_matches)

                # Update sentence index for next section
                sentence_count = len(self._split_sentences(section.get('text', '')))
                sentence_index += sentence_count
        else:
            all_matches = self.scan(
                section_text=document_text,
                base_sentence_index=0
            )

        app_logger.info(
            f"[NormativePatternScanner] Document scan complete: "
            f"{len(all_matches)} normative patterns found"
        )

        return all_matches

    def _split_sentences(self, text: str) -> List[str]:
        """Split text into sentences."""
        sentences = re.split(r'[.!?](?:\s+|$)', text)
        return [s.strip() for s in sentences if s.strip()]
