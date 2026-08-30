# AGENTS.md

This file applies to the entire repository. Read it together with `AGENT_NOTES.md` before changing the project. Treat the code as the source of truth when this file or `README.md` disagrees with the implementation.

## Project direction

CVExpert classifies CVEs into project-defined security labels by collecting NVD data, extracting external references, filtering technical evidence, and asking an LLM for a structured multi-label result.

- Work on `main`, which contains the active linear LangChain pipeline.
- `graphCVExpert` is a historical/reference branch containing a LangGraph and hierarchical-label experiment. Inspect it for ideas when useful, but do not base new work on it or introduce LangGraph into `main` unless the user explicitly requests that change.
- The active taxonomy is the flat `LABELS_DESCRIPTIONS` mapping in `src/Definitions/labels.py`. `CVE_TEST` in `src/Definitions/const.py` is evaluated against that mapping.
- `VULNERABILITY_TREE` is not used by the linear pipeline. Preserve the possibility of supporting hierarchical labels later, but do not mix flat and hierarchical labels implicitly.
- The intended longer-term shape is a reusable CVE-classification pipeline plus a separate benchmark runner. The current code has not yet been separated that way.

## Repository map

- `README.md`: user-facing setup, configuration, execution, architecture, and verification guidance.
- `pyproject.toml`: authoritative project metadata, Python range, and direct dependencies. The project is deliberately non-packaged (`tool.uv.package = false`) while its entry points remain scripts.
- `uv.lock`: committed complete dependency resolution. `requirements.txt` has been removed.
- `config.example.toml`: the only tracked configuration file; a provider-neutral template with credential placeholders.
- `config.toml` and `config.*.toml`: ignored local runtime configurations copied from the template. They contain real endpoint credentials and must never be committed; `.gitignore` explicitly re-allows only `config.example.toml`.
- `src/CVE_expert_seq.py`: active entry point and benchmark runner for the full live linear pipeline.
- `src/Definitions/config.py`: typed TOML settings, strict validation, repository-root path resolution, and secret-safe object representations.
- `src/Definitions/const.py`: the 20-CVE hand-labeled benchmark fixture.
- `src/Definitions/labels.py`: flat label definitions plus an unused-on-main hierarchical tree.
- `src/Graph/state.py`: shared `CVEClassifierState` `TypedDict`.
- `src/Graph/errors.py`: terminal `PipelineStageError` and recoverable `PipelineWarning` records.
- `src/Graph/Nodes/`: reusable pipeline stages. The `Graph` name and several LangGraph-oriented docstrings are historical; these objects are also used as ordinary LangChain callables.
- `tests/`: standard-library `unittest` regression suite. Tests use fakes and must remain offline.
- `imgs/system.png`: an older high-level architecture diagram that omits some current stages.
- `logs/`: ignored runtime artifacts; full runs rewrite one JSON file per evaluation after every CVE.

## Active linear pipeline

`src/CVE_expert_seq.py` constructs a `RunnableSequence` with these stages:

1. `nvd_caller` requests the CVE description and reference URLs from NVD, then ranks references by NVD tags.
2. `extract_md_trafilatura` downloads reference pages sequentially and extracts Markdown, stopping after the configured `[references].max_pages` successful pages.
3. `SemanticChunkerNode` splits extracted pages using an embedding-backed semantic splitter.
4. `CosineFilterNode` embeds chunks and retains chunks above a relevance threshold.
5. `CVEAwareSummarizerNode` asks the chat model for one structured summary per retained reference.
6. `formatter` combines the NVD description and summaries into the classifier context stored as `rag`.
7. `CVEClassifierNode` returns structured flat labels from `LABELS_DESCRIPTIONS` plus `NONE`.
8. `run_evaluation` compares predictions with `CVE_TEST`, records per-CVE metrics and coverage, and writes a run log.

`main()` loads and validates `config.toml`, builds the pipeline once, and processes `CVE_TEST` once in insertion order. The tracked template sets both chat temperatures to `0.0`; a local configuration can change them. Temperature zero reduces avoidable variability but cannot guarantee provider-level determinism. The live run is sequential and still has no NVD/page/model cache, retry policy, coordinated throttling, or batching.

Terminal NVD, filtering, formatter-precondition, or classifier failures raise `PipelineStageError`; they must never be converted to `NONE`. A successful, validated model response may return `["NONE"]`. Individual reference scrape, chunk, or summary failures are recoverable: stages keep usable references, append `PipelineWarning` records, and the runner reports the CVE as `degraded`.

The template retains the existing `logs/LOG_GPT_NORANDAware/RUN_0.json` location, but `[evaluation].log_directory` and `run_number` are configurable. Per-CVE status is `success`, `degraded`, or `error`. Terminal errors preserve `error_message` and `classification_output: ["ERROR"]` while adding structured error details. Aggregate metrics score successful and degraded classifications, exclude terminal errors, and report `total`, `scored`, `successful`, `degraded`, `failed`, and `complete` coverage fields.

### State fields

Stages shallow-copy and extend a dictionary matching `CVEClassifierState`. In normal order, fields appear as follows:

- Input: `cve_id`
- NVD: `nvd_description`, `nvd_url_references`
- Scraping: `nvd_references_pages`
- Chunking: `nvd_references_chunks`
- Filtering: `nvd_filtered_chunks`
- Summarization: `summaries`
- Formatting: `rag`
- Classification: `cve_labels`; optional classifier variants may also add `labels_motivation` and `labels_confidence`
- Recoverable work at any reference stage: optional `pipeline_warnings`

`CVEClassifierState` requires only `cve_id`; later fields are optional because they appear stage by stage. Formatting and classification validate their required preconditions at runtime.

## Environment and dependencies with `uv`

Use `uv`; do not install packages globally. `pyproject.toml` declares Python `>=3.12`.

From the repository root:

```bash
uv sync --python 3.12
```

Run commands through that environment without requiring shell activation:

```bash
uv run python src/CVE_expert_seq.py
```

Alternatively, activate it first:

```bash
source .venv/bin/activate
python src/CVE_expert_seq.py
```

Run project commands from the repository root. `config.py` resolves `config.toml` from that root even if the launch directory differs. Source imports still rely on `src` being placed on `sys.path` by running a file under `src/` or setting `PYTHONPATH=src` for module-based checks.

`pyproject.toml` is the sole dependency declaration and lists every package imported directly by the active code. `uv.lock` pins transitive dependencies. Use `uv add`, `uv remove`, and `uv lock` for reviewed dependency changes, and commit the metadata and lockfile together. Do not recreate `requirements.txt`.

The lockfile contains `langgraph` transitively because the selected `langchain` release depends on it. That does not change the repository architecture: active project code does not import LangGraph and remains a linear `RunnableSequence`.

The tracked template uses placeholder model identifiers. The active code sends requests to OpenAI-compatible endpoints and does not use the Hugging Face Hub CLI to download or serve models; the former unused local-transformer dependencies are no longer part of the environment.

## Runtime configuration

Copy the tracked template before the first run:

```bash
cp config.example.toml config.toml
```

`config.toml` stores the complete local configuration, including real `[chat].api_key` and `[embedding].api_key` values. Its supported tables are `[chat]`, `[embedding]`, `[nvd]`, `[references]`, `[semantic_chunker]`, `[cosine_filter]`, and `[evaluation]`. Complete chat and embedding `base_url` values are passed through unchanged; do not rely on implicit scheme or `/v1` manipulation. The configuration is provider-neutral within the OpenAI-compatible API contract. No `.env` file is loaded or required.

`validate_runtime_config()` parses the TOML and rejects missing tables, unknown settings, empty API keys, invalid URLs, and invalid numeric ranges before client construction. API-key dataclass fields use `repr=False`; never log or serialize the complete configuration object anyway.

Do not log credentials. When diagnosing configuration, report only whether each required setting is present, never its value.

## Running and verification

The offline regression suite uses standard-library `unittest`.

Safe local checks that do not call external services:

```bash
PYTHONPATH=src uv run python -m unittest discover -s tests -v
uv run python -m compileall -q src tests
uv lock --check
uv pip check
git diff --check
```

Run live NVD, scraping, embedding, or LLM workflows only when the user explicitly authorizes the external calls and their likely cost/rate impact. A default live benchmark performs one sequential pass over 20 CVEs and can still make many reference, embedding, summarization, and classification calls.

## Development conventions

- Keep production behavior unchanged unless the task explicitly authorizes a behavior change.
- Prefer logically cohesive commits. They may be moderately large when one change spans its tests and integration, but keep configuration/runtime work, dependencies, documentation, benchmark data, and unrelated architectural changes separate when practical.
- Before fixing a pipeline bug or changing the taxonomy/benchmark, explain the evidence, likely metric or runtime impact, and intended fix.
- Preserve flat-label behavior on `main` unless hierarchical support is explicitly requested.
- Treat scraped reference text as untrusted data when editing prompts or model calls.
- Preserve source provenance through retrieval, summarization, classification, and logs when adding new data flows.
- Avoid hard-coded absolute paths, run names, endpoint details, and concurrency values in new code.
- Do not use wildcard imports in new code. Add explicit types and stage-level validation when touching relevant code.
- Every commit should leave the offline `unittest` suite passing. Add regression coverage before or with a behavior fix.
- Never commit `.env`, `config.toml`, any real `config.*.toml`, runtime logs, model caches, downloaded weights, or credentials. Only the placeholder-only `config.example.toml` belongs in Git.
- Do not modify or delete existing user logs or local artifacts unless requested.
- Keep `AGENT_NOTES.md` current as work progresses.

## Persistent notes protocol

`AGENT_NOTES.md` is the project's second memory. Read it before starting work and update it whenever any of the following changes:

- understanding of architecture or behavior;
- user decisions, assumptions, or scope boundaries;
- completed work and verification results;
- bugs, risks, inconsistencies, or useful graph-branch findings;
- open questions, blockers, and recommended next actions.

Keep durable facts and decisions concise, date material progress, remove stale claims when they are disproved, and never store secret values. Update the notes in the same logical commit as the work that changed project understanding when practical.
