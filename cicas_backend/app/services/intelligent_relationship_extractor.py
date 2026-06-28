"""
Intelligent Relationship Extractor using LLM
Replaces hardcoded rules with AI-powered document relationship analysis
"""
import httpx
import json
import asyncio
from typing import List, Dict, Any, Optional, Set
from pathlib import Path
from sqlalchemy.orm import Session
from app.models.models import Standard, StandardRelationship
from app.core.config import settings
from app.core.logging_config import app_logger
from app.services.parsers.pdf_parser import PDFParser


class IntelligentRelationshipExtractor:
    """
    Uses LLM to intelligently extract relationships between standards

    Advantages over hardcoded rules:
    - Understands semantic meaning of documents
    - Detects implicit relationships
    - Adapts to different document structures
    - Can explain the reasoning behind relationships
    """

    # Relationship types we want to detect
    RELATIONSHIP_TYPES = {
        'references': 'Document A references Document B for additional context or definitions',
        'updates': 'Document A provides updates or corrections to Document B',
        'obsoletes': 'Document A replaces and renders Document B obsolete',
        'depends_on': 'Document A requires Document B to be fully understood or implemented',
        'supplements': 'Document A provides additional guidance that supplements Document B',
        'version_of': 'Document A is a different version of the same standard as Document B',
    }

    def __init__(self, db: Session):
        self.db = db
        self.api_key = settings.llm_api_key
        self.api_base = settings.llm_api_base
        self.model = settings.llm_model
        self.timeout = 300.0  # Increased to 5 minutes for large documents
        self.pdf_parser = PDFParser()

    async def extract_all_relationships(self, batch_size: int = 5):
        """Extract relationships for all standards using LLM"""
        app_logger.info("Starting intelligent relationship extraction for all standards")

        standards = self.db.query(Standard).all()
        total_relationships = 0

        # Process in batches to avoid overwhelming the API
        for i in range(0, len(standards), batch_size):
            batch = standards[i:i + batch_size]
            app_logger.info(f"Processing batch {i//batch_size + 1}/{(len(standards)-1)//batch_size + 1}")

            tasks = [self.extract_relationships_for_standard(std) for std in batch]
            results = await asyncio.gather(*tasks, return_exceptions=True)

            for result in results:
                if isinstance(result, Exception):
                    app_logger.error(f"Error in batch processing: {result}")
                else:
                    total_relationships += result

        app_logger.info(f"Extracted {total_relationships} relationships from {len(standards)} standards")
        return total_relationships

    async def extract_relationships_for_standard(self, standard: Standard) -> int:
        """
        Extract relationships for a specific standard using LLM

        Args:
            standard: Standard object

        Returns:
            Number of relationships extracted
        """
        relationships_found = 0

        try:
            # 1. Extract document text
            doc_text = await self._extract_document_text(standard)
            if not doc_text or len(doc_text) < 100:
                app_logger.warning(f"Insufficient text for {standard.title}")
                return 0

            # 2. Get candidate standards to compare against
            candidates = self._get_candidate_standards(standard)
            if not candidates:
                app_logger.info(f"No candidates found for {standard.title}")
                return 0

            # 3. Use LLM to analyze relationships
            relationships = await self._analyze_relationships_with_llm(
                standard,
                doc_text,
                candidates
            )

            # 4. Store discovered relationships
            for rel in relationships:
                self._create_relationship(
                    source_standard_id=standard.id,
                    target_standard_id=rel['target_id'],
                    relationship_type=rel['type'],
                    description=rel['description'],
                    section=rel.get('section'),
                    confidence=rel['confidence'],
                    extraction_method='llm_intelligent'
                )
                relationships_found += 1

            app_logger.info(
                f"Extracted {relationships_found} relationships for {standard.title}"
            )

        except Exception as e:
            app_logger.error(f"Error extracting relationships for {standard.id}: {e}")

        return relationships_found

    async def _extract_document_text(self, standard: Standard) -> str:
        """Extract text from document (PDF or TXT)"""
        if not standard.file_path:
            return ""

        file_path = Path(standard.file_path)
        if not file_path.exists():
            return ""

        try:
            if file_path.suffix.lower() == '.pdf':
                # Use PDF parser to extract text
                text = self.pdf_parser._extract_text_from_pdf(file_path)
                return text
            elif file_path.suffix.lower() in ['.txt', '.text']:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    return f.read()
        except Exception as e:
            app_logger.error(f"Error extracting text from {file_path}: {e}")

        return ""

    def _get_candidate_standards(self, standard: Standard, max_candidates: int = 30) -> List[Standard]:
        """
        Get candidate standards that might have relationships with the given standard

        Strategy:
        - Same source type (RFC, CABF, ETSI, etc.)
        - Cross-source relationships (all sources can reference RFCs and other standards)
        - Standards mentioned in metadata
        """
        candidates = []

        # 1. Same source type
        same_source = self.db.query(Standard).filter(
            Standard.source == standard.source,
            Standard.id != standard.id
        ).all()
        candidates.extend(same_source)

        # 2. Referenced in metadata (for RFCs)
        if standard.metadata_json:
            try:
                metadata = json.loads(standard.metadata_json)

                # Get RFCs mentioned in metadata
                for key in ['obsoletes', 'updated_by', 'updates', 'obsoleted_by']:
                    if key in metadata:
                        rfc_numbers = metadata[key]
                        if isinstance(rfc_numbers, list):
                            for rfc_num in rfc_numbers:
                                rfc = self._find_rfc_by_number(rfc_num)
                                if rfc and rfc not in candidates:
                                    candidates.append(rfc)
            except Exception as e:
                app_logger.debug(f"Error parsing metadata: {e}")

        # 3. Cross-source relationships (for all document types)
        # RFC is the foundation - everyone references it
        if standard.source != 'RFC':
            # Non-RFC documents (CABF, ETSI, Browser_CA) often reference RFCs
            rfcs = self.db.query(Standard).filter(
                Standard.source == 'RFC'
            ).limit(15).all()
            candidates.extend(rfcs)

        # CABF documents can reference each other
        if standard.source.startswith('CABF'):
            other_cabf = self.db.query(Standard).filter(
                Standard.source.like('CABF%'),
                Standard.id != standard.id
            ).all()
            candidates.extend(other_cabf)
        else:
            # Non-CABF documents can also reference CABF standards
            cabf_docs = self.db.query(Standard).filter(
                Standard.source.like('CABF%')
            ).limit(10).all()
            candidates.extend(cabf_docs)

        # ETSI documents
        if standard.source != 'ETSI':
            etsi_docs = self.db.query(Standard).filter(
                Standard.source == 'ETSI'
            ).all()
            candidates.extend(etsi_docs)

        # Browser CA documents
        if standard.source != 'Browser_CA':
            browser_docs = self.db.query(Standard).filter(
                Standard.source == 'Browser_CA'
            ).all()
            candidates.extend(browser_docs)

        # Remove duplicates and limit
        unique_candidates = list({c.id: c for c in candidates}.values())
        return unique_candidates[:max_candidates]

    async def _analyze_relationships_with_llm(
        self,
        source_standard: Standard,
        source_text: str,
        candidate_standards: List[Standard]
    ) -> List[Dict[str, Any]]:
        """
        Use LLM to analyze potential relationships between source and candidates

        Returns:
            List of relationships: [{'target_id', 'type', 'description', 'section', 'confidence'}]
        """
        # Truncate source text to manageable size (use first 8000 chars + last 2000 chars)
        if len(source_text) > 10000:
            truncated_text = source_text[:8000] + "\n\n[... middle content truncated ...]\n\n" + source_text[-2000:]
        else:
            truncated_text = source_text

        # Build candidate summary
        candidates_info = []
        for i, cand in enumerate(candidate_standards, 1):
            candidates_info.append({
                'id': cand.id,
                'index': i,
                'source': cand.source,
                'title': cand.title,
                'version': cand.version,
            })

        prompt = self._build_relationship_analysis_prompt(
            source_standard,
            truncated_text,
            candidates_info
        )

        try:
            response = await self._call_llm(prompt)
            relationships = self._parse_llm_relationship_response(response, candidate_standards)
            return relationships
        except Exception as e:
            import traceback
            app_logger.error(f"LLM analysis failed for {source_standard.title}: {type(e).__name__}: {e}")
            app_logger.error(f"Traceback: {traceback.format_exc()}")
            return []

    def _build_relationship_analysis_prompt(
        self,
        source: Standard,
        source_text: str,
        candidates: List[Dict]
    ) -> str:
        """Build prompt for LLM relationship analysis"""

        relationship_types_desc = "\n".join([
            f"- **{rtype}**: {desc}"
            for rtype, desc in self.RELATIONSHIP_TYPES.items()
        ])

        candidates_list = "\n".join([
            f"{c['index']}. [{c['source']}] {c['title']} (v{c['version']}) [ID: {c['id']}]"
            for c in candidates
        ])

        prompt = f"""You are an expert in PKI standards and document analysis. Analyze the source document and identify its relationships with candidate documents.

**Source Document:**
- Title: {source.title}
- Source: {source.source}
- Version: {source.version}

**Source Document Content (first 8000 + last 2000 chars):**
```
{source_text}
```

**Candidate Documents:**
{candidates_list}

**Relationship Types:**
{relationship_types_desc}

**Task:**
Analyze the source document content and identify which candidate documents it has relationships with. For each relationship:
1. Identify the candidate document by its index number
2. Determine the relationship type
3. Provide a brief description (1-2 sentences) explaining the relationship
4. Extract the section number where the relationship is mentioned (if applicable)
5. Assign a confidence score (0.0-1.0)

**Output Format (JSON):**
```json
{{
  "relationships": [
    {{
      "candidate_index": 1,
      "relationship_type": "references",
      "description": "Section 4.1.2.6 references RFC 5280 for certificate path validation procedures",
      "section": "4.1.2.6",
      "confidence": 0.95
    }},
    {{
      "candidate_index": 3,
      "relationship_type": "depends_on",
      "description": "This document requires understanding of RFC 6818 updates to implement correctly",
      "section": null,
      "confidence": 0.85
    }}
  ]
}}
```

**Important:**
- Only include relationships you can clearly identify from the source document
- Be conservative with confidence scores - use 1.0 only for explicit references
- If you find no relationships, return {{"relationships": []}}
- Focus on meaningful relationships, not trivial mentions

Analyze and respond:"""

        return prompt

    async def _call_llm(self, prompt: str, temperature: float = 0.1, max_tokens: int = 2000) -> str:
        """Call LLM API"""
        async with httpx.AsyncClient(timeout=self.timeout, trust_env=False) as client:
            response = await client.post(
                f"{self.api_base}/chat/completions",
                headers={
                    "Authorization": f"Bearer {self.api_key}",
                    "Content-Type": "application/json"
                },
                json={
                    "model": self.model,
                    "messages": [{"role": "user", "content": prompt}],
                    "temperature": temperature,
                    "max_tokens": max_tokens,
                }
            )

            response.raise_for_status()
            data = response.json()
            return data['choices'][0]['message']['content']

    def _parse_llm_relationship_response(
        self,
        llm_response: str,
        candidate_standards: List[Standard]
    ) -> List[Dict[str, Any]]:
        """Parse LLM response to extract relationships"""

        try:
            # Extract JSON from response (LLM might add markdown code blocks)
            json_match = llm_response
            if '```json' in llm_response:
                start = llm_response.find('```json') + 7
                end = llm_response.find('```', start)
                json_match = llm_response[start:end].strip()
            elif '```' in llm_response:
                start = llm_response.find('```') + 3
                end = llm_response.find('```', start)
                json_match = llm_response[start:end].strip()

            data = json.loads(json_match)
            relationships = []

            for rel in data.get('relationships', []):
                candidate_idx = rel.get('candidate_index')
                if not candidate_idx or candidate_idx > len(candidate_standards):
                    continue

                target_standard = candidate_standards[candidate_idx - 1]

                relationships.append({
                    'target_id': target_standard.id,
                    'type': rel.get('relationship_type'),
                    'description': rel.get('description'),
                    'section': rel.get('section'),
                    'confidence': rel.get('confidence', 0.5)
                })

            return relationships

        except Exception as e:
            app_logger.error(f"Failed to parse LLM response: {e}\nResponse: {llm_response}")
            return []

    def _create_relationship(
        self,
        source_standard_id: int,
        target_standard_id: int,
        relationship_type: str,
        description: str = None,
        section: str = None,
        confidence: float = 1.0,
        extraction_method: str = 'llm_intelligent'
    ):
        """Create a relationship record if it doesn't exist"""

        # Check if relationship already exists
        existing = self.db.query(StandardRelationship).filter(
            StandardRelationship.source_standard_id == source_standard_id,
            StandardRelationship.target_standard_id == target_standard_id,
            StandardRelationship.relationship_type == relationship_type
        ).first()

        if existing:
            # Update if LLM provides higher confidence
            if confidence > existing.confidence:
                existing.confidence = confidence
                existing.description = description or existing.description
                existing.section = section or existing.section
                existing.extraction_method = extraction_method
                self.db.commit()
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

        app_logger.info(f"Created relationship: {source_standard_id} -> {target_standard_id} ({relationship_type}, confidence={confidence:.2f})")
        return relationship

    def _find_rfc_by_number(self, rfc_number: int) -> Optional[Standard]:
        """Find an RFC standard by its number"""
        return self.db.query(Standard).filter(
            Standard.source == 'RFC',
            Standard.title.contains(f'RFC {rfc_number}')
        ).first()

