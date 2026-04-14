async def run_pipeline_logic(repo_url: str, emit_fn, user_token: Optional[str] = None):
    """
    Logic for running the pipeline (orchestrator or demo).
    """
    try:
        from pipeline_v2 import LuminaPipeline
        pipeline = LuminaPipeline(emit_fn=emit_fn, user_token=user_token)
        await pipeline.run(repo_url)

    except (ImportError, ModuleNotFoundError) as e:
        logger.warning(f"Core pipeline not found or dependencies missing (v2.0.1): {e}")
        await _demo_pipeline(emit_fn)

    except Exception as e:
        error_msg = f"Pipeline error: {str(e)}"
        logger.error(f"Pipeline execution error: {error_msg}")
        await emit_fn({"type": "error", "error": error_msg})
        await emit_fn({"type": "complete"})