"""
X.509 Certificate Field Schema — domain knowledge, not per-document configuration.

Derived from RFC 5280 Appendix A ASN.1 module definitions.
Covers the complete certificate structure including TBS fields, extensions,
and outer signature fields.

Path conventions:
- All lowercase, dot-separated: "extensions.nameconstraints.permittedsubtrees"
- No "tbscertificate." prefix (implicit)
- Extensions are under "extensions." prefix

Key APIs:
- resolve_path(raw) -> canonical path or None
- is_valid_path(path) -> bool
- get_subtree_paths(root) -> list of valid sub-paths
- format_field_hierarchy(root) -> text for LLM prompt injection
"""
import re
from typing import Optional, List, Dict, Set, Tuple


def _dn_attributes() -> Dict:
    """Subject/Issuer DN attribute nodes, shared by 'subject' and 'issuer'."""
    return {
        "commonname": {"_aliases": ["cn", "common name"]},
        "countryname": {"_aliases": ["c", "country", "country name"]},
        "stateorprovincename": {"_aliases": ["st", "state", "province", "state or province"]},
        "localityname": {"_aliases": ["l", "locality", "city"]},
        "organizationname": {"_aliases": ["o", "organization", "org"]},
        "organizationalunitname": {"_aliases": ["ou", "organizational unit"]},
        "serialnumber": {"_aliases": ["serial number attribute"]},
        "domaincomponent": {"_aliases": ["dc", "domain component"]},
        "emailaddress": {"_aliases": ["email", "rfc822"]},
        # CABF EV extensions
        "businesscategory": {"_aliases": ["business category"]},
        "jurisdictioncountryname": {"_aliases": ["jurisdiction country"]},
        "jurisdictionstateorprovincename": {"_aliases": ["jurisdiction state"]},
        "jurisdictionlocalityname": {"_aliases": ["jurisdiction locality"]},
        "streetaddress": {"_aliases": ["street", "street address"]},
        "postalcode": {"_aliases": ["postal code", "zip"]},
        "surname": {"_aliases": ["sn"]},
        "givenname": {"_aliases": ["given name"]},
        "organizationidentifier": {"_aliases": ["organization identifier"]},
    }


def _general_name_types() -> Dict:
    """GeneralName types, shared by SAN, IAN, NameConstraints subtrees."""
    return {
        "dnsname": {"_aliases": ["dns name", "domain name"]},
        "ipaddress": {"_aliases": ["ip address", "ip"]},
        "rfc822name": {"_aliases": ["email", "email address"]},
        "uniformresourceidentifier": {"_aliases": ["uri", "url"]},
        "directoryname": {"_aliases": ["directory name"]},
        "registeredid": {"_aliases": ["registered id"]},
        "othername": {"_aliases": ["other name"]},
        "x400address": {"_aliases": ["x400 address"]},
        "aboraliasedname": {},
        "edipartyname": {"_aliases": ["edi party name"]},
    }


# The complete X.509 certificate field tree
FIELD_TREE: Dict = {
    "version": {"_aliases": ["v3", "certificate version"]},
    "serialnumber": {"_aliases": ["serial number", "serial"]},
    "signature": {
        "_aliases": ["tbscertificate signature", "tbs signature"],
        "algorithm": {"_aliases": ["signature algorithm oid", "sig algorithm"]},
        "parameters": {"_aliases": ["signature parameters"]},
    },
    "issuer": {
        "_aliases": ["issuer name", "issuer dn"],
        **_dn_attributes(),
    },
    "validity": {
        "_aliases": ["certificate validity"],
        "notbefore": {"_aliases": ["not before"]},
        "notafter": {"_aliases": ["not after"]},
    },
    "subject": {
        "_aliases": ["subject name", "subject dn", "distinguished name", "distinguished names"],
        **_dn_attributes(),
        "directorystring": {"_aliases": ["directory string"]},
    },
    "subjectpublickeyinfo": {
        "_aliases": ["spki", "public key info", "subject public key info"],
        "algorithm": {
            "_aliases": ["public key algorithm", "algorithmidentifier", "algorithm identifier"],
            "algorithm": {"_aliases": ["public key algorithm oid"]},
            "parameters": {},
            "namedcurve": {"_aliases": ["ec named curve", "ecdsa curve"]},
        },
        "subjectpublickey": {"_aliases": ["public key", "publickey"]},
    },
    "extensions": {
        "basicconstraints": {
            "_aliases": ["basic constraints"],
            "ca": {"_aliases": ["ca flag", "ca boolean", "isca"]},
            "pathlenconstraint": {"_aliases": ["path length", "pathlen", "path length constraint"]},
        },
        "nameconstraints": {
            "_aliases": ["name constraints"],
            "permittedsubtrees": {
                "_aliases": ["permitted subtrees"],
                **_general_name_types(),
            },
            "excludedsubtrees": {
                "_aliases": ["excluded subtrees"],
                **_general_name_types(),
            },
            "generalsubtree": {
                "_aliases": ["general subtree"],
                "base": {},
                "minimum": {},
                "maximum": {},
            },
        },
        # issueraltname BEFORE subjectaltname: last-writer-wins ensures
        # shared GeneralName aliases (dnsname, ipaddress, ...) resolve to
        # subjectaltname children by default (the more common usage).
        "issueraltname": {
            "_aliases": ["issuer alternative name", "ian"],
            **_general_name_types(),
        },
        "subjectaltname": {
            "_aliases": ["san", "subject alternative name", "subject alt name"],
            **_general_name_types(),
        },
        "keyusage": {"_aliases": ["key usage"]},
        "extkeyusage": {"_aliases": ["extended key usage", "eku"]},
        "certificatepolicies": {"_aliases": ["certificate policies"]},
        "authoritykeyidentifier": {
            "_aliases": ["aki", "authority key identifier"],
            # RFC 5280 §4.2.1.1: AuthorityKeyIdentifier ::= SEQUENCE {
            #   keyIdentifier, authorityCertIssuer, authorityCertSerialNumber }.
            # Without these sub-fields, a rule subject naming them (especially in
            # the ASN.1-module appendix, where there is no §4.2.1.1 section to
            # anchor to) falls through to a fuzzy match on the wrong extension
            # (authorityInfoAccess). Defining them makes resolution correct.
            "keyidentifier": {"_aliases": []},
            "authoritycertissuer": {"_aliases": ["authority cert issuer"]},
            "authoritycertserialnumber": {"_aliases": ["authority cert serial number"]},
        },
        "subjectkeyidentifier": {"_aliases": ["ski", "subject key identifier"]},
        "crldistributionpoints": {"_aliases": ["crl distribution points"]},
        "authorityinfoaccess": {
            "_aliases": ["aia", "authority info access", "authority information access"]
        },
        "subjectinfoaccess": {
            "_aliases": ["sia", "subject info access", "subject information access"]
        },
        "inhibitanypolicy": {"_aliases": ["inhibit any policy", "inhibitanypolicy"]},
        "policyconstraints": {"_aliases": ["policy constraints"]},
        "policymappings": {"_aliases": ["policy mappings"]},
        "freshestcrl": {"_aliases": ["freshest crl"]},
        "subjectdirectoryattributes": {"_aliases": ["subject directory attributes"]},
    },
    # Outer Certificate-level fields (not inside TBS)
    "signaturealgorithm": {"_aliases": ["outer signature algorithm"]},
    "signaturevalue": {"_aliases": ["outer signature value"]},
}


class X509FieldSchema:
    """
    X.509 certificate field schema with path resolution and alias matching.

    Provides:
    - Alias-to-path reverse index for fast lookups
    - Path validation
    - Subtree enumeration
    - Formatted field hierarchy for LLM prompt injection
    """

    def __init__(self, field_tree: Dict = None):
        self.tree = field_tree or FIELD_TREE
        # Build indices
        self._path_to_node: Dict[str, Dict] = {}
        self._alias_to_path: Dict[str, str] = {}
        self._all_paths: Set[str] = set()
        self._extension_names: Set[str] = set()  # derived from tree
        self._build_indices()

    def _build_indices(self):
        """Build alias->path reverse index and path->node mapping."""
        self._walk_tree(self.tree, prefix="")
        # Derive extension names from tree (children of "extensions")
        ext_node = self.tree.get("extensions", {})
        self._extension_names = {
            k for k in ext_node if not k.startswith("_")
        }

    def _walk_tree(self, node: Dict, prefix: str):
        """Recursively walk the field tree to build indices.

        Uses last-writer-wins for alias deduplication. Dict insertion order
        determines which path wins for shared aliases (e.g., subjectaltname
        is listed after issueraltname so its children win for GeneralName aliases).
        """
        for key, value in node.items():
            if key.startswith("_"):
                continue

            path = f"{prefix}.{key}" if prefix else key
            self._all_paths.add(path)

            if isinstance(value, dict):
                self._path_to_node[path] = value

                # Index aliases (last-writer-wins)
                aliases = value.get("_aliases", [])
                for alias in aliases:
                    alias_lower = alias.lower()
                    self._alias_to_path[alias_lower] = path
                    no_space = alias_lower.replace(" ", "")
                    if no_space != alias_lower:
                        self._alias_to_path[no_space] = path

                # Also index the key name itself
                self._alias_to_path[key] = path

                # Recurse into children
                self._walk_tree(value, prefix=path)
            else:
                self._path_to_node[path] = {}

    def resolve_path(self, raw: str) -> Optional[str]:
        """
        Resolve a raw string to a canonical field path.

        Strategy (in priority order):
        1. Exact match against known paths
        2. Alias match (reverse index lookup)
        3. Cleaned/normalized match (remove prefixes, spaces)
        4. Partial match (try as suffix of known paths)

        Args:
            raw: Raw field reference (e.g., "permittedSubtrees dNSName", "basicConstraints")

        Returns:
            Canonical path (e.g., "extensions.nameconstraints.permittedsubtrees.dnsname") or None
        """
        if not raw:
            return None

        cleaned = raw.lower().strip()

        # Remove common prefixes
        for prefix in ("extensions.", "tbscertificate.", "certificate."):
            if cleaned.startswith(prefix):
                cleaned = cleaned[len(prefix):]

        # Strategy 1: Exact path match
        if cleaned in self._all_paths:
            return cleaned

        # Re-check with extensions. prefix
        with_ext = f"extensions.{cleaned}"
        if with_ext in self._all_paths:
            return with_ext

        # Strategy 2: Alias match
        # Try the whole string as an alias
        if cleaned in self._alias_to_path:
            return self._alias_to_path[cleaned]

        # Try without spaces
        no_space = cleaned.replace(" ", "").replace("-", "").replace("_", "")
        if no_space in self._alias_to_path:
            return self._alias_to_path[no_space]

        # Strategy 3: Split on spaces/dots and try to resolve each part
        # e.g., "permittedSubtrees dNSName" -> "extensions.nameconstraints.permittedsubtrees.dnsname"
        parts = cleaned.replace(".", " ").split()
        if len(parts) >= 2:
            # Try to find a path that ends with these parts
            parts_lower = [p.lower() for p in parts]
            for path in self._all_paths:
                path_parts = path.split(".")
                if len(path_parts) >= len(parts_lower):
                    # Check if path ends with these parts
                    tail = path_parts[-len(parts_lower):]
                    if tail == parts_lower:
                        return path

            # Try resolving parts individually and combining
            resolved_parts = []
            for part in parts_lower:
                if part in self._alias_to_path:
                    resolved_parts.append(self._alias_to_path[part])
                else:
                    resolved_parts.append(part)

            # If all parts resolved, try to find a matching path
            if resolved_parts:
                last_resolved = resolved_parts[-1]
                # Check if the last resolved part is already a full path containing parent context
                if last_resolved in self._all_paths:
                    return last_resolved

        # Strategy 4: Try as suffix
        candidates = []
        for path in self._all_paths:
            if path.endswith(f".{cleaned}") or path.endswith(f".{no_space}"):
                candidates.append(path)
        if len(candidates) == 1:
            return candidates[0]

        return None

    def is_valid_path(self, path: str) -> bool:
        """Check if a path exists in the field tree."""
        if not path:
            return False
        return path.lower() in self._all_paths

    def get_subtree_paths(self, root: str) -> List[str]:
        """Get all valid sub-paths under a given root path."""
        root_lower = root.lower()
        prefix = f"{root_lower}."
        return sorted(
            p for p in self._all_paths
            if p == root_lower or p.startswith(prefix)
        )

    def get_section_root_field(self, section_title: str) -> Optional[str]:
        """
        Infer the root field path from a section title.

        e.g., "Name Constraints" -> "extensions.nameconstraints"
              "Basic Constraints" -> "extensions.basicconstraints"
              "Subject Alternative Name" -> "extensions.subjectaltname"
              "Algorithm Object Identifiers" -> None

        Args:
            section_title: The section heading text

        Returns:
            Root field path or None if no match
        """
        if not section_title:
            return None

        title_lower = section_title.lower().strip()
        title_variants = [title_lower]

        # Titles sometimes carry trailing acronyms, e.g. "Authority Information Access (AIA)".
        # Treat those as exact-title variants, but avoid generic substring matching.
        title_without_trailing_parens = re.sub(r'\s*\([^)]*\)\s*$', '', title_lower).strip()
        if title_without_trailing_parens and title_without_trailing_parens != title_lower:
            title_variants.append(title_without_trailing_parens)

        # Try direct alias match first (whole title)
        for title in title_variants:
            if title in self._alias_to_path:
                return self._alias_to_path[title]

        # Try without common prefixes in title
        for prefix_word in ("internationalized ", "profile of ", "profile for "):
            for title in title_variants:
                if title.startswith(prefix_word):
                    stripped = title[len(prefix_word):].strip()
                    if stripped in self._alias_to_path:
                        return self._alias_to_path[stripped]

        # Fuzzy matching is intentionally conservative. Section titles like
        # "Internationalized Domain Names in Distinguished Names" contain
        # multiple generic field aliases ("domain name", "distinguished name")
        # but do not actually define a single certificate-field root. Only allow
        # substring fallback for root-level fields/extensions, never for leaf
        # aliases such as subjectAltName.dNSName.
        root_candidates: List[str] = []
        seen_candidates: Set[str] = set()
        any_match_paths: Set[str] = set()
        for alias, path in sorted(self._alias_to_path.items(), key=lambda x: -len(x[0])):
            if " " not in alias:
                continue
            if any(alias in title for title in title_variants):
                any_match_paths.add(path)
                if path.count(".") > 1:
                    continue
                if path not in seen_candidates:
                    seen_candidates.add(path)
                    root_candidates.append(path)

        if len(any_match_paths) > 1:
            return None
        if len(root_candidates) == 1:
            return root_candidates[0]

        return None

    def format_field_hierarchy(self, root: str = None, max_depth: int = 3) -> str:
        """
        Format the field tree as text for LLM prompt injection.

        Args:
            root: Optional root path to start from (None = full tree)
            max_depth: Maximum depth to display

        Returns:
            Formatted text showing the field hierarchy
        """
        lines = []
        if root:
            # Find the subtree for the given root
            root_lower = root.lower()
            node = self._path_to_node.get(root_lower)
            if node:
                lines.append(f"{root_lower}")
                self._format_node(node, root_lower, indent=1, depth=1,
                                  max_depth=max_depth, lines=lines)
            else:
                lines.append(f"(unknown root: {root})")
        else:
            self._format_node(self.tree, "", indent=0, depth=0,
                              max_depth=max_depth, lines=lines)
        return "\n".join(lines)

    def _format_node(self, node: Dict, prefix: str, indent: int,
                     depth: int, max_depth: int, lines: List[str]):
        """Recursively format a tree node."""
        if depth >= max_depth:
            # Check if there are more children
            child_count = sum(1 for k in node if not k.startswith("_"))
            if child_count > 0:
                lines.append(f"{'  ' * indent}... ({child_count} sub-fields)")
            return

        for key, value in node.items():
            if key.startswith("_"):
                continue

            path = f"{prefix}.{key}" if prefix else key
            aliases = value.get("_aliases", []) if isinstance(value, dict) else []
            alias_str = f" (aliases: {', '.join(aliases)})" if aliases else ""

            lines.append(f"{'  ' * indent}{path}{alias_str}")

            if isinstance(value, dict):
                self._format_node(value, path, indent=indent + 1,
                                  depth=depth + 1, max_depth=max_depth,
                                  lines=lines)

    def get_all_aliases(self) -> Dict[str, str]:
        """Return the complete alias->path mapping."""
        return dict(self._alias_to_path)


# Module-level singleton
_schema_instance: Optional[X509FieldSchema] = None


def get_schema() -> X509FieldSchema:
    """Get the singleton X509FieldSchema instance."""
    global _schema_instance
    if _schema_instance is None:
        _schema_instance = X509FieldSchema()
    return _schema_instance
