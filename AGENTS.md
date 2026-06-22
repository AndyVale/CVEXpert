# Agent Context: CVE Expert - Classification Pipeline

## Project Overview
This project is a LangGraph-based classification pipeline designed to map **CVEs (Common Vulnerabilities and Exposures)** into a set of user-defined security labels. It automates the process of fetching information from NVD, scraping external references, filtering technical content, and performing multi-label classification using LLMs.

## Project Structure

### Entry Point
- `src/CVE_expert_graph.py`: The main script that orchestrates the LangGraph workflow. It initializes the nodes, defines the state transitions, and compiles the graph.

### Definitions & Configuration (`src/Definitions/`)
- `const.py`: Contains constants, including the `CVE_TEST` dictionary used for evaluation and benchmarking.
- `labels.py`: Defines the custom labels and their technical descriptions used by the classifier.
- `prompts.py`: Centralized storage for LLM system prompts and templates (Summarizer, Classifier, etc.).

### Graph Logic (`src/Graph/`)
- `state.py`: Defines the `CVEClassifierState` (TypedDict). This object is passed through every node and maintains the technical context (NVD data, chunks, summaries, and final labels).
- `Nodes/`: Contains the operational logic of the pipeline, organized by task:
    - `nvd.py`: Logic for contacting the NIST NVD API.
    - `scrapers.py`: Website content extraction (e.g., Trafilatura).
    - `chunkers.py`: Text splitting strategies (Semantic, Markdown, Recursive).
    - `filters.py`: Relevance filtering (Cosine Similarity, Cross-Encoders).
    - `summarizers.py`: LLM-based technical summarization.
    - `classifiers.py`: Final LLM classification logic.
    - `formatters.py`: Logic for preparing the RAG input for the classifier.

## Implementation Details

### Node Management
- **Multiple Implementations**: Files within `src/Graph/Nodes/` often contain multiple classes for the same functional type (e.g., several different chunking strategies).
- **Pipeline Selection**: Only one class per type is typically active in the pipeline. To understand which specific implementation is currently being used, refer to the node initialization block in `src/CVE_expert_graph.py`.

### State Flow
The pipeline follows a state-machine pattern. Every node:
1. Receives the current `CVEClassifierState`.
2. Performs its specific task (e.g., filtering chunks).
3. Returns an updated version of the state.

## Developer Instructions
- **Modifying Prompts**: Edit `src/Definitions/prompts.py` to refine LLM behavior.
- **Adding Labels**: Update `src/Definitions/labels.py` to change the classification taxonomy.
- **Debugging**: Inspect `src/Graph/state.py` to understand the data keys available at any given step in the pipeline.
- **Swapping Logic**: To change a strategy (e.g., switching from Cosine Similarity to Cross-Encoder), modify the node assignment in `src/CVE_expert_graph.py`.