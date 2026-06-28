"""
FieldResolver — data-driven field resolver replacing section_topics.py hard-coded mappings.

Responsibilities:
1. section title -> root field path ("Name Constraints" -> "extensions.nameconstraints")
2. LLM raw subject -> canonical path ("permittedSubtrees dNSName" -> "extensions.nameconstraints.permittedsubtrees.dnsname")
3. Post-processing validation (check path is in field tree)

Design principle: No per-section hard-coding. Uses the X.509 field schema tree
as domain knowledge to resolve fields for any specification document.
"""
import re
from typing import Optional, Dict, List, Any

from app.services.extraction.x509_field_schema import get_schema, X509FieldSchema


class FieldResolver:
    """
    Data-driven field resolver using X.509 field schema.

    Replaces section_topics.py's canonical_subject hard-coded mappings with
    schema-driven resolution that works across all specification documents.
    """

    _GENERIC_CERTIFICATE_SUBJECTS = {
        "certificate", "the certificate", "certificates", "cert", "certs",
    }
    _GENERIC_EXTENSION_SUBJECTS = {
        "extension", "extensions", "certificate.extensions", "certificate extension",
        "certificate extensions", "the extension", "the extensions",
    }
    _NON_FIELD_PSEUDO_SUBJECT_TOKENS = {
        "profile", "requirements", "requirement", "profile.requirements",
        "clause", "section", "annex", "syntax", "semantics",
        "definition", "definitions", "format", "encoding",
        "semanticsidentifier", "semanticsidentifiers",
    }

    def __init__(self, schema: X509FieldSchema = None):
        self.schema = schema or get_schema()

    def _strip_common_prefixes(self, value: str) -> str:
        cleaned = value.lower().strip()

        # Strip bare "tbscertificate" that appears without a field suffix
        if cleaned == "tbscertificate":
            return "certificate"

        # Strip prefixes
        for prefix in ("extensions.", "tbscertificate.", "certificate."):
            if cleaned.startswith(prefix):
                return cleaned[len(prefix):]
        return cleaned

    def _looks_like_non_field_subject(self, value: str) -> bool:
        normalized = value.lower().strip().replace("_", ".")
        if not normalized:
            return False
        if normalized == "certificate":
            return False
        if normalized in self._GENERIC_CERTIFICATE_SUBJECTS:
            return False
        if normalized in self._GENERIC_EXTENSION_SUBJECTS:
            return False
        parts = [part for part in re.split(r"[.\s/-]+", normalized) if part]
        if not parts:
            return False
        return any(part in self._NON_FIELD_PSEUDO_SUBJECT_TOKENS for part in parts)

    def _prefer_section_root_subject(
        self,
        cleaned: str,
        section_root: str = None,
    ) -> Optional[str]:
        if not section_root:
            return None

        section_root_lower = section_root.lower()
        if cleaned in self._GENERIC_CERTIFICATE_SUBJECTS:
            return "certificate"
        if cleaned in self._GENERIC_EXTENSION_SUBJECTS:
            return section_root_lower if section_root_lower.startswith("extensions.") else "extensions"
        if self._looks_like_non_field_subject(cleaned):
            return section_root_lower
        return None

    def resolve_section_subject(
        self,
        section_title: str,
        section_id: str = None,
    ) -> Optional[Dict[str, Any]]:
        """
        Infer canonical subject from section title.

        Strategy (by priority):
        1. Exact match: title field name directly matches a tree node
        2. Alias match: title words match a node's _aliases
        3. section_id hierarchy inference: 4.2.1.x -> extensions child

        Args:
            section_title: Section heading text (e.g., "Name Constraints")
            section_id: Section number (e.g., "4.2.1.10")

        Returns:
            dict with 'path', 'aliases', 'instruction' or None
        """
        if not section_title:
            return None

        # Try schema-based resolution from title
        root_field = self.schema.get_section_root_field(section_title)

        if root_field:
            node = self.schema._path_to_node.get(root_field, {})
            aliases = node.get("_aliases", [])
            subtree_paths = self.schema.get_subtree_paths(root_field)

            return {
                "path": root_field,
                "aliases": aliases,
                "subtree_paths": subtree_paths,
                "instruction": (
                    f"All rules in this section MUST use subject paths from the "
                    f"'{root_field}' field hierarchy. "
                    f"Use the most specific sub-path matching the rule's scope. "
                    f"Valid sub-paths: {', '.join(subtree_paths[:15])}"
                    + (f" ... ({len(subtree_paths)} total)" if len(subtree_paths) > 15 else "")
                ),
            }

        return None

    def normalize_subject(
        self,
        raw_subject: str,
        section_root: str = None,
    ) -> str:
        """
        Normalize an LLM-output raw subject to a canonical path.

        Strategy:
        1. Clean: lowercase, strip spaces, remove common prefixes
        2. If section_root provided, try resolving within section subtree first
        3. Exact match in field tree (global)
        4. Alias match (reverse index)
        5. If section_root provided, try resolving as sub-path
        6. Return original (lowercased) if unresolvable

        Args:
            raw_subject: LLM-output subject string
            section_root: Optional section root field (e.g., "extensions.nameconstraints")

        Returns:
            Canonical path string
        """
        if not raw_subject:
            return raw_subject

        # Step 1: Clean
        cleaned = self._strip_common_prefixes(raw_subject)

        preferred_root_subject = self._prefer_section_root_subject(cleaned, section_root)
        if preferred_root_subject:
            return preferred_root_subject

        # Step 2: If section_root provided, try resolving within section subtree FIRST
        # This prevents e.g. "subjectaltname" resolving globally when section is nameconstraints
        if section_root:
            section_root_lower = section_root.lower()
            subtree_paths = self.schema.get_subtree_paths(section_root_lower)

            # Generic certificate/extension mentions should anchor to the current section root.
            if cleaned == section_root_lower.split(".")[-1]:
                return section_root_lower
            if cleaned == section_root_lower or cleaned.startswith(section_root_lower + "."):
                if self.schema.is_valid_path(cleaned):
                    return cleaned

            # Try prepending section root
            candidate = f"{section_root_lower}.{cleaned}"
            if self.schema.is_valid_path(candidate):
                return candidate

            # Try resolving cleaned parts within section subtree
            for path in subtree_paths:
                path_parts = path.split(".")
                if path_parts[-1] == cleaned:
                    return path
                if cleaned.replace(" ", ".") in path:
                    return path

            # Try alias resolution within section context
            resolved_with_context = self.schema.resolve_path(
                f"{section_root_lower} {cleaned}"
            )
            if resolved_with_context and resolved_with_context.startswith(section_root_lower):
                return resolved_with_context

            # If the subject looks like a pseudo-field reference, anchor it to the section root
            # instead of returning unstable free-form paths like profile.requirements.
            if self._looks_like_non_field_subject(cleaned):
                return section_root_lower

        # Step 3 & 4: Try schema resolution (handles exact + alias match)
        resolved = self.schema.resolve_path(cleaned)
        if resolved:
            # Normalize generic certificate-level references to the canonical root node.
            if resolved in {"version", "serialnumber", "signature", "issuer", "validity", "subject",
                            "subjectpublickeyinfo", "signaturealgorithm", "signaturevalue"}:
                return resolved

            # If section_root is set, check if resolved path is in a different
            # extension subtree. If so, check for a better match within section_root.
            if section_root and resolved != section_root:
                section_root_lower = section_root.lower()
                section_ext = section_root_lower.split(".")[1] if "." in section_root_lower else ""
                resolved_ext = resolved.split(".")[1] if resolved.startswith("extensions.") and "." in resolved else ""

                if (section_ext and resolved_ext
                        and section_ext != resolved_ext
                        and resolved.startswith("extensions.")):
                    # Resolved to a different extension — try to find leaf in section subtree
                    leaf = resolved.split(".")[-1]
                    subtree_paths = self.schema.get_subtree_paths(section_root_lower)
                    for path in subtree_paths:
                        if path.split(".")[-1] == leaf:
                            return path
                    # No match in section subtree; fall back to global but use section_root
                    # if the resolved path is just an extension name (not a specific sub-field)
                    resolved_parts = resolved.split(".")
                    if len(resolved_parts) <= 2:
                        # e.g. "extensions.subjectaltname" → use section_root instead
                        return section_root_lower

            return resolved

        # Step 5: Try original raw (maybe with extensions prefix)
        resolved_raw = self.schema.resolve_path(raw_subject)
        if resolved_raw:
            return resolved_raw

        # Return cleaned path (preserve info, don't lose it)
        return cleaned

    def validate_and_fix_subject(
        self,
        ir_subject: str,
        section_root: str = None,
    ) -> str:
        """
        Post-processing: validate subject path and attempt to fix common errors.

        Args:
            ir_subject: Subject path from the IR
            section_root: Optional root field for context

        Returns:
            Validated/fixed subject path
        """
        if not ir_subject:
            return ir_subject

        subject_lower = ir_subject.lower().strip()

        # Hard-stop for unstable pseudo-field leftovers: prefer section root or generic certificate.
        if self._looks_like_non_field_subject(subject_lower):
            if section_root:
                return section_root.lower()
            if any(token in subject_lower for token in ("certificate", "cert")):
                return "certificate"
        # If already valid, return as-is
        if self.schema.is_valid_path(subject_lower):
            return subject_lower

        # Try normalization

        # Try normalization
        normalized = self.normalize_subject(ir_subject, section_root)
        if self.schema.is_valid_path(normalized):
            return normalized

        # Common fixes:
        # 1. Missing "extensions." prefix for extension fields
        # Extension names derived from tree, not hard-coded
        ext_names = self.schema._extension_names
        first_part = subject_lower.split(".")[0]
        if first_part in ext_names:
            fixed = f"extensions.{subject_lower}"
            if self.schema.is_valid_path(fixed):
                return fixed

        # 2. Compound paths like "basicconstraints.keyusage.keycertsign"
        #    -> should just be "extensions.keyusage"
        parts = subject_lower.split(".")
        for part in parts:
            if part in ext_names:
                candidate = f"extensions.{part}"
                if self.schema.is_valid_path(candidate):
                    # Check if there's a more specific valid sub-path
                    remaining = parts[parts.index(part) + 1:]
                    if remaining:
                        sub_candidate = f"{candidate}.{'.'.join(remaining)}"
                        if self.schema.is_valid_path(sub_candidate):
                            return sub_candidate
                    return candidate

        # 3. If section_root is provided and subject doesn't start with it,
        #    the subject might be relative to section_root
        if section_root:
            section_lower = section_root.lower()
            if not subject_lower.startswith(section_lower):
                fixed = self.normalize_subject(subject_lower, section_root)
                if self.schema.is_valid_path(fixed):
                    return fixed

        # 4. Fix DN attribute typos (e.g., subject.surnamename -> subject.surname)
        if subject_lower.startswith("subject."):
            attr = subject_lower[len("subject."):]
            fixed_attr = self._fix_dn_typo(attr)
            if fixed_attr and fixed_attr != attr:
                return f"subject.{fixed_attr}"

        # Return normalized form even if not in tree
        return normalized

    def _fix_dn_typo(self, attr_name: str) -> Optional[str]:
        """
        Fix common LLM typos in DN attribute names.

        E.g., 'surnamename' -> 'surname', 'commoname' -> 'commonname'
        Uses edit distance of 1-2 against known DN attributes.
        """
        # Get valid DN attribute names from the subject subtree
        subject_subtree = self.schema.get_subtree_paths("subject")
        dn_attrs = set()
        for p in subject_subtree:
            parts = p.split(".")
            if len(parts) == 2 and parts[0] == "subject":
                dn_attrs.add(parts[1])

        if attr_name in dn_attrs:
            return attr_name  # already valid

        # Try removing duplicated suffix (surnamename → surname)
        for attr in dn_attrs:
            if attr_name.startswith(attr) and len(attr_name) > len(attr):
                extra = attr_name[len(attr):]
                # "surnamename" → surname + "name" (suffix is a common word fragment)
                if attr.endswith(extra) or extra in ("name", "string", "type"):
                    return attr

        # Try edit distance <= 2
        best_match = None
        best_dist = 3
        for attr in dn_attrs:
            if abs(len(attr) - len(attr_name)) > 2:
                continue
            dist = self._edit_distance(attr_name, attr)
            if dist < best_dist:
                best_dist = dist
                best_match = attr
        if best_match and best_dist <= 2:
            return best_match

        return None

    @staticmethod
    def _edit_distance(s1: str, s2: str) -> int:
        """Simple Levenshtein edit distance."""
        if len(s1) < len(s2):
            return FieldResolver._edit_distance(s2, s1)
        if len(s2) == 0:
            return len(s1)
        prev = list(range(len(s2) + 1))
        for i, c1 in enumerate(s1):
            curr = [i + 1]
            for j, c2 in enumerate(s2):
                curr.append(min(
                    prev[j + 1] + 1,
                    curr[j] + 1,
                    prev[j] + (0 if c1 == c2 else 1)
                ))
            prev = curr
        return prev[len(s2)]

    def get_field_hierarchy_prompt(self, section_root: str = None) -> str:
        """
        Generate the field hierarchy text for LLM prompt injection.

        Args:
            section_root: Optional root to limit hierarchy display

        Returns:
            Formatted hierarchy text
        """
        if section_root:
            return self.schema.format_field_hierarchy(root=section_root, max_depth=4)
        else:
            return self.schema.format_field_hierarchy(max_depth=3)


# Module-level singleton
_resolver_instance: Optional[FieldResolver] = None


def get_field_resolver() -> FieldResolver:
    """Get the singleton FieldResolver instance."""
    global _resolver_instance
    if _resolver_instance is None:
        _resolver_instance = FieldResolver()
    return _resolver_instance
