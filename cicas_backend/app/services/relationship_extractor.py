"""
Standard Document Relationship Extractor
Extracts relationships between standard documents
"""
import re
from typing import List, Dict, Any, Optional
from pathlib import Path
from sqlalchemy.orm import Session
from app.models.models import Standard, StandardRelationship
from app.core.logging_config import app_logger


class RelationshipExtractor:
    """Extracts relationships between standards documents"""

    # RFC reference patterns
    RFC_PATTERNS = [
        r'RFC\s*(\d{4,5})',  # RFC 5280
        r'rfc(\d{4,5})',     # rfc5280
        r'\[RFC(\d{4,5})\]', # [RFC5280]
    ]

    # CABF reference patterns
    CABF_PATTERNS = [
        r'Baseline\s+Requirements',
        r'\bBR\b',
        r'EV\s+Guidelines',
        r'Network\s+Security\s+Requirements',
        r'S/MIME\s+Baseline\s+Requirements',
    ]

    def __init__(self, db: Session):
        self.db = db

    def extract_all_relationships(self):
        """Extract relationships for all standards in database"""
        app_logger.info("Starting relationship extraction for all standards")

        standards = self.db.query(Standard).all()
        total_relationships = 0

        for standard in standards:
            count = self.extract_relationships_for_standard(standard)
            total_relationships += count

        app_logger.info(f"Extracted {total_relationships} relationships from {len(standards)} standards")
        return total_relationships

    def extract_relationships_for_standard(self, standard: Standard) -> int:
        """
        Extract relationships for a specific standard

        Args:
            standard: Standard object

        Returns:
            Number of relationships extracted
        """
        relationships_found = 0

        try:
            # 1. Extract metadata-based relationships (for RFCs)
            if standard.source == "RFC":
                relationships_found += self._extract_rfc_metadata_relationships(standard)

            # 2. Extract version relationships (same doc, different versions)
            relationships_found += self._extract_version_relationships(standard)

            # 3. Extract text-based references (from document content)
            if standard.file_path:
                relationships_found += self._extract_text_references(standard)

            # 4. Extract CABF working group dependencies
            if standard.source == "CABF":
                relationships_found += self._extract_cabf_dependencies(standard)

            app_logger.info(
                f"Extracted {relationships_found} relationships for {standard.source} - {standard.title}"
            )

        except Exception as e:
            app_logger.error(f"Error extracting relationships for standard {standard.id}: {e}")

        return relationships_found

    def _extract_rfc_metadata_relationships(self, standard: Standard) -> int:
        """
        Extract relationships from RFC metadata

        RFC documents often include metadata like:
        - Obsoletes: RFC 3280, RFC 4325
        - Updated by: RFC 6818
        """
        count = 0

        if not standard.metadata_json:
            return 0

        import json
        try:
            metadata = json.loads(standard.metadata_json)

            # Handle obsoletes relationship
            if 'obsoletes' in metadata:
                obsoletes_list = metadata['obsoletes']
                if isinstance(obsoletes_list, list):
                    for rfc_number in obsoletes_list:
                        target = self._find_rfc_by_number(rfc_number)
                        if target and target.id != standard.id:
                            self._create_relationship(
                                source_standard_id=standard.id,
                                target_standard_id=target.id,
                                relationship_type='obsoletes',
                                description=f'RFC {standard.title} obsoletes this RFC',
                                extraction_method='automatic_metadata'
                            )
                            count += 1

            # Handle updated_by relationship
            if 'updated_by' in metadata:
                updated_by_list = metadata['updated_by']
                if isinstance(updated_by_list, list):
                    for rfc_number in updated_by_list:
                        target = self._find_rfc_by_number(rfc_number)
                        if target and target.id != standard.id:
                            self._create_relationship(
                                source_standard_id=target.id,
                                target_standard_id=standard.id,
                                relationship_type='updates',
                                description=f'RFC {target.title} updates this RFC',
                                extraction_method='automatic_metadata'
                            )
                            count += 1

        except json.JSONDecodeError as e:
            app_logger.error(f"Error parsing metadata JSON for standard {standard.id}: {e}")

        return count

    def _extract_version_relationships(self, standard: Standard) -> int:
        """Extract version relationships between documents of the same type"""
        count = 0

        if not standard.version:
            return 0

        # Find other versions of the same standard
        # Match by source and title (excluding version number)
        title_pattern = re.sub(r'v?\d+\.\d+(\.\d+)?', '', standard.title).strip()

        similar_standards = self.db.query(Standard).filter(
            Standard.source == standard.source,
            Standard.id != standard.id
        ).all()

        for other in similar_standards:
            # Check if titles are similar (excluding version)
            other_title_pattern = re.sub(r'v?\d+\.\d+(\.\d+)?', '', other.title).strip()

            if self._are_titles_similar(title_pattern, other_title_pattern):
                # Check if there's a version relationship
                if standard.version and other.version:
                    if self._is_newer_version(standard.version, other.version):
                        # standard is newer than other
                        self._create_relationship(
                            source_standard_id=standard.id,
                            target_standard_id=other.id,
                            relationship_type='version_of',
                            description=f'Version {standard.version} is newer than version {other.version}',
                            extraction_method='automatic_metadata'
                        )
                        count += 1

        return count

    def _extract_text_references(self, standard: Standard) -> int:
        """Extract references from document text"""
        count = 0

        try:
            file_path = Path(standard.file_path)
            if not file_path.exists():
                return 0

            # Read document content
            if file_path.suffix.lower() in ['.txt', '.text']:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
            elif file_path.suffix.lower() == '.pdf':
                # For PDF, we'd need to extract text first
                # This is simplified - in production, use PDF parser
                app_logger.debug(f"PDF text extraction not yet implemented for {file_path}")
                return 0
            else:
                return 0

            # Find RFC references
            rfc_numbers = set()
            for pattern in self.RFC_PATTERNS:
                matches = re.findall(pattern, content, re.IGNORECASE)
                rfc_numbers.update(int(m) for m in matches)

            # Create reference relationships
            for rfc_number in rfc_numbers:
                target = self._find_rfc_by_number(rfc_number)
                if target and target.id != standard.id:
                    # Check if relationship already exists
                    existing = self.db.query(StandardRelationship).filter(
                        StandardRelationship.source_standard_id == standard.id,
                        StandardRelationship.target_standard_id == target.id,
                        StandardRelationship.relationship_type == 'references'
                    ).first()

                    if not existing:
                        self._create_relationship(
                            source_standard_id=standard.id,
                            target_standard_id=target.id,
                            relationship_type='references',
                            description=f'References RFC {rfc_number}',
                            extraction_method='automatic_text',
                            confidence=0.9
                        )
                        count += 1

        except Exception as e:
            app_logger.error(f"Error extracting text references for standard {standard.id}: {e}")

        return count

    def _extract_cabf_dependencies(self, standard: Standard) -> int:
        """Extract dependencies for CABF documents"""
        count = 0

        # EV Guidelines depends on BR
        if 'ev' in standard.title.lower() and 'guideline' in standard.title.lower():
            br_standard = self.db.query(Standard).filter(
                Standard.source == 'CABF',
                Standard.title.contains('Baseline Requirements')
            ).first()

            if br_standard:
                self._create_relationship(
                    source_standard_id=standard.id,
                    target_standard_id=br_standard.id,
                    relationship_type='depends_on',
                    description='EV Guidelines depend on Baseline Requirements',
                    extraction_method='automatic_metadata'
                )
                count += 1

        # NetSec supplements BR
        if 'network' in standard.title.lower() and 'security' in standard.title.lower():
            br_standard = self.db.query(Standard).filter(
                Standard.source == 'CABF',
                Standard.title.contains('Baseline Requirements')
            ).first()

            if br_standard:
                self._create_relationship(
                    source_standard_id=standard.id,
                    target_standard_id=br_standard.id,
                    relationship_type='supplements',
                    description='Network Security Requirements supplement Baseline Requirements',
                    extraction_method='automatic_metadata'
                )
                count += 1

        return count

    def _create_relationship(
        self,
        source_standard_id: int,
        target_standard_id: int,
        relationship_type: str,
        description: str = None,
        section: str = None,
        confidence: float = 1.0,
        extraction_method: str = 'automatic'
    ):
        """Create a relationship record if it doesn't exist"""

        # Check if relationship already exists
        existing = self.db.query(StandardRelationship).filter(
            StandardRelationship.source_standard_id == source_standard_id,
            StandardRelationship.target_standard_id == target_standard_id,
            StandardRelationship.relationship_type == relationship_type
        ).first()

        if existing:
            app_logger.debug(f"Relationship already exists: {source_standard_id} -> {target_standard_id} ({relationship_type})")
            return existing

        # Create new relationship
        relationship = StandardRelationship(
            source_standard_id=source_standard_id,
            target_standard_id=target_standard_id,
            relationship_type=relationship_type,
            description=description,
            section=section,
            confidence=confidence,
            extraction_method=extraction_method,
            is_active=True
        )

        self.db.add(relationship)
        self.db.commit()

        app_logger.debug(f"Created relationship: {source_standard_id} -> {target_standard_id} ({relationship_type})")
        return relationship

    def _find_rfc_by_number(self, rfc_number: int) -> Optional[Standard]:
        """Find an RFC standard by its number"""
        return self.db.query(Standard).filter(
            Standard.source == 'RFC',
            Standard.title.contains(f'RFC {rfc_number}')
        ).first()

    def _are_titles_similar(self, title1: str, title2: str) -> bool:
        """Check if two titles are similar (fuzzy match)"""
        # Simple implementation - can be improved with fuzzy matching
        t1 = title1.lower().strip()
        t2 = title2.lower().strip()

        # Remove common words
        common_words = {'the', 'a', 'an', 'for', 'and', 'or', 'of', 'in', 'to'}
        t1_words = set(w for w in t1.split() if w not in common_words)
        t2_words = set(w for w in t2.split() if w not in common_words)

        # Check overlap
        if not t1_words or not t2_words:
            return False

        overlap = len(t1_words & t2_words) / max(len(t1_words), len(t2_words))
        return overlap > 0.6

    def _is_newer_version(self, version1: str, version2: str) -> bool:
        """Compare two version strings"""
        try:
            # Parse version strings (e.g., "1.8.0" or "v1.8.0")
            v1_parts = [int(x) for x in re.findall(r'\d+', version1)]
            v2_parts = [int(x) for x in re.findall(r'\d+', version2)]

            # Pad to same length
            max_len = max(len(v1_parts), len(v2_parts))
            v1_parts += [0] * (max_len - len(v1_parts))
            v2_parts += [0] * (max_len - len(v2_parts))

            # Compare
            return v1_parts > v2_parts

        except Exception:
            return False

    def get_relationships_for_standard(self, standard_id: int) -> Dict[str, List[Dict]]:
        """
        Get all relationships for a specific standard

        Returns:
            Dict with 'outgoing' and 'incoming' relationships
        """
        outgoing = self.db.query(StandardRelationship).filter(
            StandardRelationship.source_standard_id == standard_id,
            StandardRelationship.is_active == True
        ).all()

        incoming = self.db.query(StandardRelationship).filter(
            StandardRelationship.target_standard_id == standard_id,
            StandardRelationship.is_active == True
        ).all()

        return {
            'outgoing': [self._relationship_to_dict(r) for r in outgoing],
            'incoming': [self._relationship_to_dict(r) for r in incoming]
        }

    def _relationship_to_dict(self, relationship: StandardRelationship) -> Dict:
        """Convert relationship to dictionary"""
        source = self.db.query(Standard).get(relationship.source_standard_id)
        target = self.db.query(Standard).get(relationship.target_standard_id)

        return {
            'id': relationship.id,
            'relationship_type': relationship.relationship_type,
            'description': relationship.description,
            'section': relationship.section,
            'confidence': relationship.confidence,
            'extraction_method': relationship.extraction_method,
            'source_standard': {
                'id': source.id,
                'title': source.title,
                'source': source.source,
                'version': source.version
            } if source else None,
            'target_standard': {
                'id': target.id,
                'title': target.title,
                'source': target.source,
                'version': target.version
            } if target else None
        }

    def get_relationship_graph(self) -> Dict[str, Any]:
        """
        Get the entire relationship graph

        Returns:
            Dict with 'nodes' (standards) and 'edges' (relationships)
        """
        standards = self.db.query(Standard).all()
        relationships = self.db.query(StandardRelationship).filter(
            StandardRelationship.is_active == True
        ).all()

        nodes = []
        for std in standards:
            nodes.append({
                'id': std.id,
                'label': f"{std.source} - {std.title[:50]}{'...' if len(std.title) > 50 else ''}",
                'title': std.title,
                'source': std.source,
                'version': std.version,
                'group': std.source  # For coloring nodes by source
            })

        edges = []
        for rel in relationships:
            edges.append({
                'id': rel.id,
                'from': rel.source_standard_id,
                'to': rel.target_standard_id,
                'label': rel.relationship_type,
                'title': rel.description or rel.relationship_type,
                'type': rel.relationship_type,
                'confidence': rel.confidence
            })

        return {
            'nodes': nodes,
            'edges': edges,
            'statistics': {
                'total_standards': len(nodes),
                'total_relationships': len(edges),
                'relationship_types': self._count_relationship_types(relationships)
            }
        }

    def _count_relationship_types(self, relationships: List[StandardRelationship]) -> Dict[str, int]:
        """Count relationships by type"""
        counts = {}
        for rel in relationships:
            counts[rel.relationship_type] = counts.get(rel.relationship_type, 0) + 1
        return counts
