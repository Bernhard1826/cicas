"""
API routes for standard document relationships
"""
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from typing import Dict, Any, List
from app.core.database import get_db
from app.services.relationship_extractor import RelationshipExtractor
from app.services.intelligent_relationship_extractor import IntelligentRelationshipExtractor
from app.models.models import Standard, StandardRelationship
from app.core.logging_config import app_logger

router = APIRouter(prefix="/api/relationships", tags=["relationships"])


@router.post("/extract/all")
async def extract_all_relationships(db: Session = Depends(get_db)):
    """
    Extract relationships for all standards in the database

    This will analyze all documents and extract:
    - References (from document content)
    - Updates/Obsoletes (from RFC metadata)
    - Version relationships
    - Dependencies between CABF documents
    """
    try:
        extractor = RelationshipExtractor(db)
        count = extractor.extract_all_relationships()

        return {
            "status": "success",
            "message": f"Successfully extracted {count} relationships",
            "relationships_count": count
        }

    except Exception as e:
        app_logger.error(f"Error extracting relationships: {e}")
        raise HTTPException(status_code=500, detail=str(e))




@router.post("/extract/all/intelligent")
async def extract_all_relationships_intelligent(
    batch_size: int = Query(5, description="Batch size for LLM processing"),
    db: Session = Depends(get_db)
):
    """
    Extract relationships for all standards using LLM (RECOMMENDED)
    
    This intelligent extractor:
    - Uses LLM to understand document semantics
    - Detects implicit relationships
    - Provides confidence scores and explanations
    - Works with PDF documents
    - More accurate than rule-based extraction
    
    Args:
        batch_size: Number of documents to process concurrently (default: 5)
    """
    try:
        extractor = IntelligentRelationshipExtractor(db)
        count = await extractor.extract_all_relationships(batch_size=batch_size)
        
        return {
            "status": "success",
            "message": f"Successfully extracted {count} relationships using LLM",
            "relationships_count": count,
            "extraction_method": "llm_intelligent"
        }
    
    except Exception as e:
        app_logger.error(f"Error in intelligent relationship extraction: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/extract/standard/{standard_id}/intelligent")
async def extract_standard_relationships_intelligent(
    standard_id: int,
    db: Session = Depends(get_db)
):
    """
    Extract relationships for a specific standard using LLM (RECOMMENDED)
    
    Args:
        standard_id: ID of the standard to process
    """
    try:
        # Check if standard exists
        standard = db.query(Standard).get(standard_id)
        if not standard:
            raise HTTPException(status_code=404, detail="Standard not found")
        
        extractor = IntelligentRelationshipExtractor(db)
        count = await extractor.extract_relationships_for_standard(standard)
        
        return {
            "status": "success",
            "message": f"Extracted {count} relationships for standard {standard_id} using LLM",
            "standard": {
                "id": standard.id,
                "title": standard.title,
                "source": standard.source
            },
            "relationships_count": count,
            "extraction_method": "llm_intelligent"
        }
    
    except HTTPException:
        raise
    except Exception as e:
        app_logger.error(f"Error in intelligent extraction for standard {standard_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/extract/standard/{standard_id}")
async def extract_standard_relationships(
    standard_id: int,
    db: Session = Depends(get_db)
):
    """
    Extract relationships for a specific standard

    Args:
        standard_id: ID of the standard to process
    """
    try:
        # Check if standard exists
        standard = db.query(Standard).get(standard_id)
        if not standard:
            raise HTTPException(status_code=404, detail="Standard not found")

        extractor = RelationshipExtractor(db)
        count = extractor.extract_relationships_for_standard(standard)

        return {
            "status": "success",
            "message": f"Extracted {count} relationships for standard {standard_id}",
            "standard": {
                "id": standard.id,
                "title": standard.title,
                "source": standard.source
            },
            "relationships_count": count
        }

    except HTTPException:
        raise
    except Exception as e:
        app_logger.error(f"Error extracting relationships for standard {standard_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/standard/{standard_id}")
async def get_standard_relationships(
    standard_id: int,
    db: Session = Depends(get_db)
):
    """
    Get all relationships for a specific standard

    Returns both outgoing (this standard references others)
    and incoming (others reference this standard) relationships
    """
    try:
        # Check if standard exists
        standard = db.query(Standard).get(standard_id)
        if not standard:
            raise HTTPException(status_code=404, detail="Standard not found")

        extractor = RelationshipExtractor(db)
        relationships = extractor.get_relationships_for_standard(standard_id)

        return {
            "status": "success",
            "standard": {
                "id": standard.id,
                "title": standard.title,
                "source": standard.source,
                "version": standard.version
            },
            "relationships": relationships
        }

    except HTTPException:
        raise
    except Exception as e:
        app_logger.error(f"Error getting relationships for standard {standard_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/graph")
async def get_relationship_graph(
    source: str = None,
    db: Session = Depends(get_db)
):
    """
    Get the complete relationship graph

    Args:
        source: Optional filter by source (RFC, CABF, etc.)

    Returns:
        Graph data with nodes and edges suitable for visualization
    """
    try:
        extractor = RelationshipExtractor(db)
        graph = extractor.get_relationship_graph()

        # Filter by source if specified
        if source:
            filtered_node_ids = {
                node['id'] for node in graph['nodes']
                if node['source'] == source
            }
            graph['nodes'] = [
                node for node in graph['nodes']
                if node['id'] in filtered_node_ids
            ]
            graph['edges'] = [
                edge for edge in graph['edges']
                if edge['from'] in filtered_node_ids and edge['to'] in filtered_node_ids
            ]
            graph['statistics']['total_standards'] = len(graph['nodes'])
            graph['statistics']['total_relationships'] = len(graph['edges'])

        return {
            "status": "success",
            "graph": graph
        }

    except Exception as e:
        app_logger.error(f"Error getting relationship graph: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/statistics")
async def get_relationship_statistics(db: Session = Depends(get_db)):
    """
    Get statistics about document relationships
    """
    try:
        total_relationships = db.query(StandardRelationship).filter(
            StandardRelationship.is_active == True
        ).count()

        # Count by type
        relationships = db.query(StandardRelationship).filter(
            StandardRelationship.is_active == True
        ).all()

        type_counts = {}
        for rel in relationships:
            type_counts[rel.relationship_type] = type_counts.get(rel.relationship_type, 0) + 1

        # Count by extraction method
        method_counts = {}
        for rel in relationships:
            method_counts[rel.extraction_method] = method_counts.get(rel.extraction_method, 0) + 1

        return {
            "status": "success",
            "statistics": {
                "total_relationships": total_relationships,
                "by_type": type_counts,
                "by_extraction_method": method_counts
            }
        }

    except Exception as e:
        app_logger.error(f"Error getting relationship statistics: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/standard/{standard_id}")
async def delete_standard_relationships(
    standard_id: int,
    db: Session = Depends(get_db)
):
    """
    Delete all relationships for a specific standard

    This removes both outgoing and incoming relationships
    """
    try:
        # Delete outgoing relationships
        outgoing_count = db.query(StandardRelationship).filter(
            StandardRelationship.source_standard_id == standard_id
        ).delete()

        # Delete incoming relationships
        incoming_count = db.query(StandardRelationship).filter(
            StandardRelationship.target_standard_id == standard_id
        ).delete()

        db.commit()

        return {
            "status": "success",
            "message": f"Deleted {outgoing_count + incoming_count} relationships",
            "outgoing_deleted": outgoing_count,
            "incoming_deleted": incoming_count
        }

    except Exception as e:
        db.rollback()
        app_logger.error(f"Error deleting relationships for standard {standard_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/types")
async def get_relationship_types():
    """
    Get available relationship types with descriptions
    """
    return {
        "status": "success",
        "relationship_types": [
            {
                "type": "references",
                "description": "Document references another document (e.g., BR references RFC 5280)"
            },
            {
                "type": "updates",
                "description": "Document updates another document (e.g., RFC 6818 updates RFC 5280)"
            },
            {
                "type": "obsoletes",
                "description": "Document obsoletes another document (e.g., RFC 5280 obsoletes RFC 3280)"
            },
            {
                "type": "depends_on",
                "description": "Document depends on another document (e.g., EV Guidelines depend on BR)"
            },
            {
                "type": "supplements",
                "description": "Document supplements another document (e.g., NetSec supplements BR)"
            },
            {
                "type": "version_of",
                "description": "Different versions of the same document (e.g., BR v2.0.0 and BR v2.0.1)"
            }
        ]
    }
