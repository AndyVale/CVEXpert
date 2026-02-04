from Graph.state import CVEClassifierState

def formatter(state: CVEClassifierState):
    nvd_desc = state["references"][0]
    # External summaries are secondary, providing technical depth
    if state["summarized_references"]:
        ref_sections = []
        tech_references = [t_ref for t_ref in state["summarized_references"] if t_ref]
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
    return {**state, "rag": rag_text}
