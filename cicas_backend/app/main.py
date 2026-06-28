"""
Main FastAPI application
"""
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pathlib import Path
from app.core.config import settings
from app.core.logging_config import app_logger
from app.core.database import init_db
from app.api import routes
from app.api import statistics_routes
from app.api import rule_extraction_routes
from app.api import intelligent_routing_routes
from app.api import extraction_accuracy_routes
from app.api import relationship_routes
from app.api import zlint_analysis_routes
from app.api import knowledge_graph_routes
from app.api import similarity_routes
from app.api import codegen_routes
from app.api import zlint_enhanced_routes
from app.api import structured_ir_routes  # 受控 IR 提取（新架构）
from app.api import lintability_analysis_routes  # 规则可执行性分析
from app.services.knowledge_layer.knowledge_initializer import initialize_knowledge_layer

# Create FastAPI app
app = FastAPI(
    title="PKI Standards Management System",
    description="PKI standards extraction, lintability analysis, and zlint code generation system",
    version="1.0.0"
)

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure appropriately for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
app.include_router(routes.router, prefix="/api/v1", tags=["standards"])
app.include_router(statistics_routes.router, tags=["statistics"])
app.include_router(rule_extraction_routes.router, tags=["rule-extraction"])
app.include_router(intelligent_routing_routes.router, tags=["intelligent-routing"])
app.include_router(extraction_accuracy_routes.router, tags=["extraction-accuracy"])
app.include_router(relationship_routes.router, tags=["relationships"])
app.include_router(zlint_analysis_routes.router, tags=["zlint-analysis"])
app.include_router(knowledge_graph_routes.router, prefix="/api/v1", tags=["knowledge-graph"])
app.include_router(similarity_routes.router, tags=["document-alignment"])
app.include_router(codegen_routes.router, prefix="/api/v1/codegen", tags=["codegen"])
# Register same router with /rule-to-ir prefix for IR display page compatibility
app.include_router(codegen_routes.router, prefix="/api/v1/rule-to-ir", tags=["rule-to-ir"])
app.include_router(zlint_enhanced_routes.router, tags=["zlint-enhanced-generation"])
app.include_router(structured_ir_routes.router, tags=["structured-ir-extraction"])  # 受控 IR 提取
app.include_router(lintability_analysis_routes.router, tags=["lintability-analysis"])  # 规则可执行性分析

# Mount static files
static_dir = Path(__file__).parent.parent / "static"
if static_dir.exists():
    app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")
    app_logger.info(f"Static files mounted from: {static_dir}")

@app.on_event("startup")
async def startup_event():
    """Initialize application on startup"""
    app_logger.info("Starting PKI Standards Management System")
    app_logger.info(f"Database: {settings.database_url}")

    # Initialize knowledge layer (load RFC/CABF/ETSI documents)
    data_dir = str(Path(__file__).parent.parent / "data")
    try:
        init_result = initialize_knowledge_layer(data_dir)
        if init_result.success:
            app_logger.info(
                f"Knowledge layer initialized: "
                f"{init_result.rfc_loaded} RFC, "
                f"{init_result.cabf_loaded} CABF, "
                f"{init_result.etsi_loaded} ETSI documents"
            )
        else:
            app_logger.warning(
                f"Knowledge layer initialization had errors: {init_result.errors}"
            )
    except Exception as e:
        app_logger.error(f"Knowledge layer initialization failed: {e}", exc_info=True)

@app.on_event("shutdown")
async def shutdown_event():
    """Cleanup on shutdown"""
    app_logger.info("Shutting down PKI Standards Management System")


@app.get("/")
async def root():
    """Root endpoint"""
    return {
        "name": "PKI Standards Management System",
        "version": "1.0.0",
        "status": "running",
        "docs": "/docs"
    }


@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "timestamp": "2025-10-26"
    }


if __name__ == "__main__":
    import uvicorn

    app_logger.info(f"Starting server on {settings.api_host}:{settings.api_port}")

    uvicorn.run(
        "app.main:app",
        host=settings.api_host,
        port=settings.api_port,
        reload=settings.api_reload,
        log_level=settings.log_level.lower()
    )






