from Graph.errors import PipelineStageError
from Graph.reporting import get_logger
from Graph.state import CVEClassifierState


LOGGER = get_logger("format")


def formatter(state: CVEClassifierState) -> CVEClassifierState:
    cve_id = state.get("cve_id", "Unknown")
    LOGGER.debug("Classification-context formatting started for %s", cve_id)
    try:
        nvd_desc = state["nvd_description"]
        summaries = state["summaries"]
        if not isinstance(nvd_desc, str) or not nvd_desc.strip():
            raise ValueError("nvd_description must be a non-empty string")
        if not isinstance(summaries, dict):
            raise TypeError("summaries must be a dictionary")
    except (KeyError, TypeError, ValueError) as error:
        raise PipelineStageError(
            stage="format",
            cve_id=cve_id,
            error=error,
            safe_message="Required formatter input is missing or invalid",
        ) from error

    if summaries:
        ref_sections = []
        tech_references = [summary for summary in summaries.values() if summary]
        for i, x in enumerate(tech_references):
            ref_sections.append(f"[Technical Insight from Reference {i+1}]\n{x}")
        references_text = "\n\n".join(ref_sections)
    else:
        references_text = "No additional technical references provided."

    rag_text = f"""--- PRIMARY SOURCE: NVD DESCRIPTION ---
{nvd_desc}

--- SECONDARY SOURCES: TECHNICAL SUMMARIES ---
{references_text}
"""
    LOGGER.debug(
        "Classification-context formatting completed for %s: summaries=%s context_chars=%s",
        cve_id,
        len(summaries),
        len(rag_text),
    )
    return {**state, "rag": rag_text}
