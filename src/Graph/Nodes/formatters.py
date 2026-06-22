from Graph.state import CVEClassifierState

def formatter(state: CVEClassifierState) -> CVEClassifierState:
    nvd_desc = state["nvd_description"]

    if state["summaries"]:
        ref_sections = []
        for url, summary in state.get("summaries", {}).items():
            if summary:
                ref_sections.append(f"[Technical Insight from Reference: {url}]\n{summary}")
        references_text = "\n\n".join(ref_sections)
    else:
        references_text = "No additional technical references provided."

    rag_text = f"""--- PRIMARY SOURCE: NVD DESCRIPTION ---
{nvd_desc}

--- SECONDARY SOURCES: TECHNICAL SUMMARIES ---
{references_text}
"""
    return {**state, "rag": rag_text}
