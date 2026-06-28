"""
Semantic Similar Rules Discovery Routes (语义相似规则发现路由)
API endpoints for cross-document similar rule discovery
Uses pure semantic vector similarity approach
"""
from fastapi import APIRouter, HTTPException, Depends, Query
from sqlalchemy.orm import Session
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field

from app.core.database import get_db
from app.core.logging_config import app_logger
from app.models.models import Standard, Rule
from app.services.similarity.semantic_similar_rule_engine import SemanticSimilarRuleEngine


router = APIRouter(prefix="/api/v1/similarity", tags=["similarity"])


# Request/Response models
class DocumentRulesRequest(BaseModel):
    """Request model for document rules"""
    source_doc: str = Field(..., description="Document identifier (e.g., RFC5280)")
    rules: List[Dict[str, Any]] = Field(..., description="List of rules from the document")


class AlignmentRequest(BaseModel):
    """Request model for document alignment"""
    documents: List[DocumentRulesRequest] = Field(..., description="List of documents to align")
    similarity_threshold: float = Field(0.85, ge=0.0, le=1.0, description="Cosine similarity threshold for grouping")
    min_group_size: int = Field(2, ge=2, description="Minimum group size")


class DocumentStandardRequest(BaseModel):
    """Request model for aligning rules from database standards"""
    standard_ids: List[int] = Field(..., description="List of standard IDs to align")
    similarity_threshold: float = Field(0.85, ge=0.0, le=1.0, description="Cosine similarity threshold for grouping")
    min_group_size: int = Field(2, ge=2, description="Minimum group size")
    limit_per_standard: Optional[int] = Field(None, description="Limit number of rules per standard")


@router.post("/align-documents")
async def align_documents(request: AlignmentRequest):
    """
    Discover semantically similar rules across multiple documents

    Analyzes semantic similarity between rules from different documents
    using pure semantic vector approach

    Returns:
    - similarity_groups: List of similar rule groups
    - statistics: Summary statistics
    """
    try:
        app_logger.info(f"Discovering similar rules in {len(request.documents)} documents")

        # Initialize semantic similar rule engine
        config = {
            "similarity_threshold": request.similarity_threshold,
            "min_group_size": request.min_group_size,
        }
        engine = SemanticSimilarRuleEngine(config=config)

        # Convert request to engine format
        documents = [
            {
                "source_doc": doc.source_doc,
                "rules": doc.rules
            }
            for doc in request.documents
        ]

        # Perform similar rule discovery
        results = await engine.discover_similar_rules(documents=documents)

        app_logger.info(f"Discovery complete: {results['statistics']['total_similarity_groups']} groups found")

        return {
            "success": True,
            "data": results
        }

    except Exception as e:
        app_logger.error(f"Error in document alignment: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/align-standards")
async def align_standards(request: DocumentStandardRequest, db: Session = Depends(get_db)):
    """
    Discover similar rules from database standards

    Fetches rules from specified standards in the database
    and performs semantic similarity analysis

    Returns:
    - similarity_groups: List of similar rule groups
    - statistics: Summary statistics
    """
    try:
        app_logger.info(f"Discovering similar rules in {len(request.standard_ids)} standards from database")

        # Fetch standards from database
        standards = db.query(Standard).filter(Standard.id.in_(request.standard_ids)).all()

        if len(standards) != len(request.standard_ids):
            found_ids = [s.id for s in standards]
            missing_ids = [sid for sid in request.standard_ids if sid not in found_ids]
            raise HTTPException(
                status_code=404,
                detail=f"Standards not found: {missing_ids}"
            )

        # Build documents from standards
        documents = []

        for standard in standards:
            # Fetch rules for this standard
            # Note: Don't filter by status - include all rules for similarity discovery
            rules_query = db.query(Rule).filter(
                Rule.standard_id == standard.id
            )

            # Apply limit if specified
            if request.limit_per_standard:
                rules_query = rules_query.limit(request.limit_per_standard)

            rules = rules_query.all()

            app_logger.info(f"Found {len(rules)} rules for standard {standard.id} ({standard.source} {standard.version})")

            # Convert to dictionaries
            rule_dicts = [
                {
                    "id": rule.id,
                    "section": rule.section,
                    "text": rule.text,
                }
                for rule in rules
            ]

            documents.append({
                "source_doc": f"{standard.source} {standard.version or ''}".strip(),
                "rules": rule_dicts
            })

        app_logger.info(f"Loaded {sum(len(d['rules']) for d in documents)} total rules from {len(documents)} standards")

        # Initialize semantic similar rule engine
        config = {
            "similarity_threshold": request.similarity_threshold,
            "min_group_size": request.min_group_size,
        }
        engine = SemanticSimilarRuleEngine(config=config)

        # Perform similar rule discovery
        results = await engine.discover_similar_rules(documents=documents)

        app_logger.info(f"Discovery complete: {results['statistics']['total_similarity_groups']} groups found")

        return {
            "success": True,
            "data": results
        }

    except HTTPException:
        raise
    except Exception as e:
        app_logger.error(f"Error in standard alignment: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/available-standards")
async def get_available_standards(db: Session = Depends(get_db)):
    """
    Get list of available standards for alignment

    Returns list of standards with their rule counts
    """
    try:
        standards = db.query(Standard).filter(Standard.is_latest == True).all()

        result = []
        for standard in standards:
            rule_count = db.query(Rule).filter(
                Rule.standard_id == standard.id
            ).count()

            result.append({
                "id": standard.id,
                "source": standard.source,
                "title": standard.title,
                "version": standard.version,
                "rule_count": rule_count,
                "publish_date": standard.publish_date.isoformat() if standard.publish_date else None,
            })

        return {
            "success": True,
            "data": result
        }

    except Exception as e:
        app_logger.error(f"Error fetching available standards: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/alignment-stats/{standard_id_1}/{standard_id_2}")
async def get_alignment_stats(
    standard_id_1: int,
    standard_id_2: int,
    similarity_threshold: float = 0.90,
    db: Session = Depends(get_db)
):
    """
    Get quick alignment statistics between two standards

    Returns summary statistics without full alignment details
    """
    try:
        # Verify standards exist
        standard1 = db.query(Standard).filter(Standard.id == standard_id_1).first()
        standard2 = db.query(Standard).filter(Standard.id == standard_id_2).first()

        if not standard1 or not standard2:
            raise HTTPException(status_code=404, detail="One or both standards not found")

        # Perform lightweight alignment
        request = DocumentStandardRequest(
            standard_ids=[standard_id_1, standard_id_2],
            similarity_threshold=similarity_threshold,
            use_clustering=True,
            min_cluster_size=2
        )

        results = await align_standards(request, db)

        # Return only statistics
        return {
            "success": True,
            "data": {
                "standard_1": {
                    "id": standard1.id,
                    "source": standard1.source,
                    "version": standard1.version,
                },
                "standard_2": {
                    "id": standard2.id,
                    "source": standard2.source,
                    "version": standard2.version,
                },
                "statistics": results["data"]["statistics"]
            }
        }

    except HTTPException:
        raise
    except Exception as e:
        app_logger.error(f"Error getting alignment stats: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))

