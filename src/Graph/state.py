from typing import TypedDict

class CVEClassifierState(TypedDict):
    cve_id: str
    references: list[str]
    rag: str
    output: str