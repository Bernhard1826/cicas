"""
Deterministic canonicalization for unstable lintability-driving IR fields.

This layer sits after LLM extraction and before final lintable computation.
It rewrites only the canonical classification fields that feed the four-condition
rule engine: rule_category, verifiability, assertion_subject, and
enforcement_phase.
"""
from __future__ import annotations

import re
from typing import Optional

from .ir_schema import (
    AssertionSubject,
    EnforcementPhase,
    IntermediateRepresentation,
    RuleCategory,
    Verifiability,
)


class IRCanonicalizer:
    """Deterministically stabilize lintability-driving IR fields."""

    CERTIFICATE_SUBJECT_PREFIXES = (
        "certificate.",
        "certificate",
        "subject",
        "issuer",
        "validity",
        "signature",
        "signaturealgorithm",
        "subjectpublickeyinfo",
        "publickey",
        "extensions.",
        "tbscertificate",
        "serialnumber",
        "version",
    )

    IMPLEMENTATION_SUBJECT_HINTS = (
        "implementation",
        "validator",
        "client",
        "software",
        "application",
        "library",
    )

    RUNTIME_PHRASES = (
        "when comparing",
        "before comparing",
        "case-insensitive",
        "case insensitive",
        "for comparison",
        "during validation",
        "when validating",
        "path validation",
        "certificate path",
        "verify signature",
        "verify signatures",
        "used to verify",
        "relying party",
    )

    DISPLAY_PHRASES = (
        "before display",
        "for display",
        "displayed",
        "display as",
        "to unicode",
        "tounicode",
    )

    ALGORITHM_REF_PHRASES = (
        "as specified in rfc",
        "as described in rfc",
        "described in section",
        "specified in section",
        "perform the operation specified in",
        "algorithm specified in",
        "stringprep",
        "toascii",
    )

    ENCODING_KEYWORDS = (
        "encoded as",
        "encoded in",
        "der encoding",
        "der-encoded",
        "ia5string",
        "utf8string",
        "printablestring",
        "bmpstring",
        "universalstring",
        "teletexstring",
        "visible string",
        "asn.1",
        "octet string",
        "bit string",
        "non-negative integer",
        "non-negative",
        "must be present",
        "shall be present",
        "must not be present",
        "shall not be present",
        "marked critical",
        "marked non-critical",
        "critical extension",
        "must contain",
        "shall contain",
        "must include",
        "shall include",
        "must not exceed",
        "shall not exceed",
        "contains the ace-encoded value",
        "ace-encoded",
        "before storage",
        "stored in the certificate",
    )

    COMPARISON_KEYWORDS = (
        "compare",
        "comparison",
        "match",
        "matching",
        "label-by-label",
        "for equality",
        "equal to",
    )

    LITERAL_ENCODING_MATCH_PHRASES = (
        "hex-encoded bytes",
        "hex encoded bytes",
        "byte-for-byte identical",
        "algorithmidentifier",
        "algorithm identifier",
        "subjectpublickeyinfo",
        "signaturealgorithm field",
        "parameters field",
        "null parameter",
    )

    CONTEXT_DEPENDENT_PHRASES = (
        "technically constrained",
        "mozilla's root store",
        "mozilla’s root store",
        "mozilla's program",
        "mozilla’s program",
    )

    OPERATIONAL_POLICY_PHRASES = (
        "publicly disclose",
        "disclosed in the ccadb",
        "disclose in the ccadb",
        "ccadb",
        "freely available",
        "without additional requirements",
        "audited in accordance with this policy",
        "operated in accordance with this policy",
    )

    CA_BEHAVIOR_PHRASES = (
        "ca shall",
        "ca must",
        "issuing ca",
        "applicant",
        "subscriber",
        "registration authority",
        "repository",
        "ocsp",
        "crl",
        "audit",
        "log",
        "document",
        "maintain",
    )

    PROCEDURAL_PHRASES = (
        "ca shall verify",
        "ca must verify",
        "ca shall confirm",
        "ca must confirm",
        "ca shall validate",
        "ca must validate",
        "ca shall ensure",
        "ca must ensure",
        "ca shall revoke",
        "ca must revoke",
        "ca shall review",
        "ca must review",
        "ca shall reject",
        "ca must reject",
        "ca shall check",
        "ca must check",
        "ca shall document",
        "ca must document",
        "ra shall",
        "ra must",
        "issuance process",
        "prior to issuance",
        "before issuing",
        "upon revocation",
        "identity validation",
        "vetting process",
    )

    OPERATIONAL_PHRASES = (
        "crl must be",
        "crl shall be",
        "ocsp responder",
        "ocsp response",
        "must be available",
        "shall be available",
        "must publish",
        "shall publish",
        "within 24 hours",
        "within 48 hours",
        "must maintain",
        "shall maintain",
        "must retain",
        "shall retain",
        "must archive",
        "shall archive",
        "repository must",
        "repository shall",
        "must log",
        "shall log",
        "audit log",
    )

    EXTERNAL_VALIDATION_PHRASES = (
        "verify via dns",
        "verify via http",
        "dns lookup",
        "http request",
        "domain validation",
        "domain control",
        "whois",
        "caa record",
        "dns txt record",
        "challenge-response",
        "verify ownership",
        "prove control",
        "external source",
        "third-party",
        "third party",
        "out-of-band",
    )

    def canonicalize(self, ir: IntermediateRepresentation) -> IntermediateRepresentation:
        """Canonicalize unstable fields, then recompute lintable."""
        text = self._combined_text(ir)
        subject_path = self._subject_path(ir)

        self._canonicalize_subject_and_phase(ir, text, subject_path)
        self._canonicalize_rule_category(ir, text, subject_path)
        self._canonicalize_verifiability(ir, text, subject_path)

        ir.recompute_lintable()
        return ir

    def _combined_text(self, ir: IntermediateRepresentation) -> str:
        parts = [
            getattr(ir, "rule_text", None),
            getattr(ir, "canonical_text", None),
        ]
        return " ".join(part for part in parts if part).lower()

    def _subject_path(self, ir: IntermediateRepresentation) -> str:
        subject = getattr(ir, "subject", None)
        if hasattr(subject, "path"):
            return (subject.path or "").lower()
        return str(subject or "").lower()

    def _set_subject(self, ir: IntermediateRepresentation, value: AssertionSubject) -> None:
        ir.assertion_subject = value.value

    def _set_phase(self, ir: IntermediateRepresentation, value: Optional[EnforcementPhase]) -> None:
        ir.enforcement_phase = value.value if value else None

    def _set_category(self, ir: IntermediateRepresentation, value: RuleCategory) -> None:
        ir.rule_category = value.value

    def _set_verifiability(self, ir: IntermediateRepresentation, value: Verifiability) -> None:
        ir.verifiability = value.value

    def _canonicalize_subject_and_phase(self, ir: IntermediateRepresentation, text: str, subject_path: str) -> None:
        if self._has_any(text, self.DISPLAY_PHRASES):
            self._set_subject(ir, AssertionSubject.IMPLEMENTATION)
            self._set_phase(ir, None)
            return

        if self._looks_operational_policy(text):
            self._set_subject(ir, AssertionSubject.IMPLEMENTATION)
            self._set_phase(ir, EnforcementPhase.PROCESSING)
            return

        if self._looks_observable_literal_match_constraint(text, subject_path):
            self._set_subject(ir, AssertionSubject.CERTIFICATE)
            self._set_phase(ir, EnforcementPhase.ENCODING)
            return

        if self._has_any(text, self.RUNTIME_PHRASES) or self._has_any(text, self.COMPARISON_KEYWORDS):
            self._set_subject(ir, AssertionSubject.RELYING_PARTY)
            self._set_phase(ir, EnforcementPhase.COMPARISON)
            return

        if self._has_any(text, self.CA_BEHAVIOR_PHRASES):
            self._set_subject(ir, AssertionSubject.CA)
            if "validate" in text or "validation" in text:
                self._set_phase(ir, EnforcementPhase.VALIDATION)
            return

        if subject_path.startswith(self.CERTIFICATE_SUBJECT_PREFIXES):
            self._set_subject(ir, AssertionSubject.CERTIFICATE)
            if self._looks_runtime_validation(text):
                self._set_phase(ir, EnforcementPhase.VALIDATION)
            elif self._looks_encoding(text, subject_path):
                self._set_phase(ir, EnforcementPhase.ENCODING)
            return

        if any(hint in subject_path for hint in self.IMPLEMENTATION_SUBJECT_HINTS):
            self._set_subject(ir, AssertionSubject.IMPLEMENTATION)
            if self._looks_runtime_validation(text):
                self._set_phase(ir, EnforcementPhase.PROCESSING)

    def _canonicalize_rule_category(self, ir: IntermediateRepresentation, text: str, subject_path: str) -> None:
        if self._has_any(text, self.DISPLAY_PHRASES):
            self._set_category(ir, RuleCategory.DISPLAY)
            return

        if self._looks_operational_policy(text):
            self._set_category(ir, RuleCategory.CAPABILITY)
            return

        if self._looks_observable_literal_match_constraint(text, subject_path):
            self._set_category(ir, RuleCategory.ENCODING_CONSTRAINT)
            return

        if self._looks_runtime_comparison(text):
            self._set_category(ir, RuleCategory.COMPARISON)
            return

        if self._looks_algorithm_ref(text, subject_path):
            self._set_category(ir, RuleCategory.ALGORITHM_REF)
            return

        if self._looks_capability(text, subject_path):
            self._set_category(ir, RuleCategory.CAPABILITY)
            return

        if self._looks_encoding(text, subject_path):
            self._set_category(ir, RuleCategory.ENCODING_CONSTRAINT)
            return

        # Legacy category families collapsed into current schema.
        if self._looks_external_validation(text):
            self._set_category(ir, RuleCategory.CLARIFICATION)
            return

        if self._looks_procedural(text, subject_path):
            self._set_category(ir, RuleCategory.CLARIFICATION)
            return

        if self._looks_operational(text, subject_path):
            self._set_category(ir, RuleCategory.CLARIFICATION)
            return

        if self._looks_semantic_definition(text):
            self._set_category(ir, RuleCategory.DEFINITION)
            return

        if self._looks_clarification(text, subject_path):
            self._set_category(ir, RuleCategory.CLARIFICATION)

    def _canonicalize_verifiability(self, ir: IntermediateRepresentation, text: str, subject_path: str) -> None:
        category = getattr(ir, "rule_category", None)
        if hasattr(category, "value"):
            category = category.value

        if category in {
            RuleCategory.DISPLAY.value,
            RuleCategory.CAPABILITY.value,
            RuleCategory.DEFINITION.value,
        }:
            if category == RuleCategory.CAPABILITY.value and self._looks_operational_policy(text):
                self._set_verifiability(ir, Verifiability.RUNTIME_ONLY)
            else:
                self._set_verifiability(ir, Verifiability.NONE)
            return

        if category == RuleCategory.ALGORITHM_REF.value:
            if self._looks_encoding(text, subject_path):
                self._set_verifiability(ir, Verifiability.OBSERVABLE)
            else:
                self._set_verifiability(ir, Verifiability.NONE)
            return

        if self._looks_context_dependent_certificate_constraint(text, subject_path):
            self._set_verifiability(ir, Verifiability.CONTEXT_DEPENDENT)
            return

        if self._looks_observable_literal_match_constraint(text, subject_path):
            self._set_verifiability(ir, Verifiability.OBSERVABLE)
            return

        if category == RuleCategory.COMPARISON.value or self._looks_runtime_comparison(text):
            self._set_verifiability(ir, Verifiability.RUNTIME_ONLY)
            return

        if getattr(ir, "assertion_subject", None) == AssertionSubject.CERTIFICATE.value and self._looks_encoding(text, subject_path):
            self._set_verifiability(ir, Verifiability.OBSERVABLE)
            return

        if self._looks_runtime_validation(text):
            self._set_verifiability(ir, Verifiability.RUNTIME_ONLY)

    def _looks_runtime_validation(self, text: str) -> bool:
        return any(phrase in text for phrase in (
            "validation",
            "validate",
            "when processing",
            "during processing",
            "when evaluating",
        ))

    def _looks_runtime_comparison(self, text: str) -> bool:
        if self._looks_observable_literal_match_constraint(text, ""):
            return False
        return self._has_any(text, self.RUNTIME_PHRASES) or (
            self._has_any(text, self.COMPARISON_KEYWORDS) and "before storage" not in text
        )

    def _looks_algorithm_ref(self, text: str, subject_path: str) -> bool:
        if not self._has_any(text, self.ALGORITHM_REF_PHRASES):
            return False
        # If the rule constrains a certificate field's encoding, it's an
        # encoding constraint that *references* an algorithm — not a pure
        # algorithm step.  E.g. "MUST convert to ACE as specified in RFC 3490"
        # constrains the dNSName encoding result, even though it mentions an RFC.
        if self._looks_encoding(text, subject_path):
            return False
        if subject_path.startswith(self.CERTIFICATE_SUBJECT_PREFIXES):
            # Subject is a certificate field — check for encoding-result semantics
            encoding_result_hints = (
                "ace", "ascii compatible encoding", "stored in",
                "must contain", "shall contain", "must be stored",
                "shall be stored", "must include", "shall include",
            )
            if self._has_any(text, encoding_result_hints):
                return False
        return True

    def _looks_capability(self, text: str, subject_path: str) -> bool:
        capability_markers = (
            "implementations must allow",
            "must allow for",
            "must support",
            "must be capable",
            "increased space requirements",
        )
        if self._has_any(text, capability_markers):
            return "before storage" not in text and not subject_path.startswith(self.CERTIFICATE_SUBJECT_PREFIXES)
        return False

    def _looks_encoding(self, text: str, subject_path: str) -> bool:
        if self._has_any(text, self.ENCODING_KEYWORDS):
            return True
        if subject_path.startswith(self.CERTIFICATE_SUBJECT_PREFIXES):
            encoding_patterns = (
                r"\bmust be [a-z0-9\- ]+string\b",
                r"\bshall be [a-z0-9\- ]+string\b",
                r"\bmust not exceed \d+",
                r"\bshall not exceed \d+",
                r"\bmust be non-negative\b",
                r"\bshall be non-negative\b",
                r"\bmust be set to\b",
                r"\bshall be set to\b",
            )
            return any(re.search(pattern, text) for pattern in encoding_patterns)
        return False

    def _looks_observable_literal_match_constraint(self, text: str, subject_path: str) -> bool:
        if subject_path and not subject_path.startswith(self.CERTIFICATE_SUBJECT_PREFIXES):
            return False

        has_match_language = self._has_any(text, self.COMPARISON_KEYWORDS) or "identical" in text
        if not has_match_language:
            return False

        if "when comparing" in text or "before comparing" in text or "for comparison" in text:
            return False

        cross_certificate_markers = (
            "certification path",
            "issuing ca certificate",
            "existing ca certificate",
            "subsequent certificate",
            "chain up to",
            "chain to",
            "mozilla's root store",
            "mozilla’s root store",
            "mozilla's program",
            "mozilla’s program",
        )
        if self._has_any(text, cross_certificate_markers):
            return False

        has_literal_target = (
            self._has_any(text, self.LITERAL_ENCODING_MATCH_PHRASES)
            or bool(re.search(r"\b[0-9a-f]{8,}\b", text))
            or bool(re.search(r"\b(?:\d+\.){3,}\d+\b", text))
        )
        return has_literal_target

    def _looks_context_dependent_certificate_constraint(self, text: str, subject_path: str) -> bool:
        if not subject_path.startswith(self.CERTIFICATE_SUBJECT_PREFIXES):
            return False
        return self._has_any(text, self.CONTEXT_DEPENDENT_PHRASES)

    def _looks_operational_policy(self, text: str) -> bool:
        return self._has_any(text, self.OPERATIONAL_POLICY_PHRASES)

    def _looks_semantic_definition(self, text: str) -> bool:
        definition_patterns = (
            r"\bindicates whether\b",
            r"\bis one of\b",
            r"\bis limited to\b",
            r"\bmeans that\b",
            r"\bdefines?\b",
        )
        return any(re.search(pattern, text) for pattern in definition_patterns) and not self._looks_encoding(text, "")

    def _looks_clarification(self, text: str, subject_path: str) -> bool:
        if subject_path.startswith(self.CERTIFICATE_SUBJECT_PREFIXES):
            clarification_markers = (
                "if the certificate",
                "if present",
                "consistent with",
                "only when",
                "unless",
            )
            return self._has_any(text, clarification_markers)
        return False

    def _looks_procedural(self, text: str, subject_path: str) -> bool:
        """CA/RA behavioral requirements — issuance policy, verification steps."""
        if subject_path.startswith(self.CERTIFICATE_SUBJECT_PREFIXES):
            return False  # Certificate field constraints are not procedural
        return self._has_any(text, self.PROCEDURAL_PHRASES)

    def _looks_operational(self, text: str, subject_path: str) -> bool:
        """Deployment/operational requirements — CRL, OCSP, logging, availability."""
        if subject_path.startswith(self.CERTIFICATE_SUBJECT_PREFIXES):
            return False
        return self._has_any(text, self.OPERATIONAL_PHRASES)

    def _looks_external_validation(self, text: str) -> bool:
        """Rules requiring external world state — DNS, HTTP, domain ownership."""
        return self._has_any(text, self.EXTERNAL_VALIDATION_PHRASES)

    def _has_any(self, text: str, phrases: tuple[str, ...]) -> bool:
        return any(phrase in text for phrase in phrases)
