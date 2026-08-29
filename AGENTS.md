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

- `README.md`: short project statement. It is incomplete and should not be relied on for setup or architecture details.
- `requirements.txt`: unpinned dependency ranges. There is no `pyproject.toml`, lockfile, package metadata, or CI configuration.
- `src/CVE_expert_seq.py`: active entry point and benchmark runner for the full live linear pipeline.
- `src/test.py`: replay experiment that reads a previous JSON log and reruns later stages. It is not an automated test and currently contains a machine-specific absolute path.
- `src/Definitions/config.py`: constants, model names, repository-root `.env` loading, and mode-aware runtime validation.
- `src/Definitions/const.py`: the 20-CVE hand-labeled benchmark fixture.
- `src/Definitions/labels.py`: flat label definitions plus an unused-on-main hierarchical tree.
- `src/Graph/state.py`: shared `CVEClassifierState` `TypedDict`.
- `src/Graph/errors.py`: terminal `PipelineStageError` and recoverable `PipelineWarning` records.
- `src/Graph/Nodes/`: reusable pipeline stages. The `Graph` name and several LangGraph-oriented docstrings are historical; these objects are also used as ordinary LangChain callables.
- `tests/`: standard-library `unittest` regression suite. Tests use fakes and must remain offline.
- `imgs/system.png`: an older high-level architecture diagram that omits some current stages.
- `logs/`: ignored runtime artifacts; full runs rewrite one JSON file per evaluation after every CVE.
- `.env`: ignored local credentials and endpoints. Never print, commit, or paste its values.

## Active linear pipeline

`src/CVE_expert_seq.py` constructs a `RunnableSequence` with these stages:

1. `nvd_caller` requests the CVE description and reference URLs from NVD, then ranks references by NVD tags.
2. `extract_md_trafilatura` downloads reference pages sequentially and extracts Markdown, stopping after `REF_MAX` successful pages.
3. `SemanticChunkerNode` splits extracted pages using an embedding-backed semantic splitter.
4. `CosineFilterNode` embeds chunks and retains chunks above a relevance threshold.
5. `CVEAwareSummarizerNode` asks the chat model for one structured summary per retained reference.
6. `formatter` combines the NVD description and summaries into the classifier context stored as `rag`.
7. `CVEClassifierNode` returns structured flat labels from `LABELS_DESCRIPTIONS` plus `NONE`.
8. `run_evaluation` compares predictions with `CVE_TEST`, records per-CVE metrics and coverage, and writes a run log.

`main()` builds the pipeline once and processes `CVE_TEST` once in insertion order. The summarizer and classifier both use temperature `0.0`; this reduces avoidable variability but cannot guarantee provider-level determinism. The live run is sequential and still has no NVD/page/model cache, retry policy, coordinated throttling, or batching.

Terminal NVD, filtering, formatter-precondition, or classifier failures raise `PipelineStageError`; they must never be converted to `NONE`. A successful, validated model response may return `["NONE"]`. Individual reference scrape, chunk, or summary failures are recoverable: stages keep usable references, append `PipelineWarning` records, and the runner reports the CVE as `degraded`.

Run logs retain the existing `logs/LOG_GPT_NORANDAware/RUN_0.json` location and artifact fields. Per-CVE status is `success`, `degraded`, or `error`. Terminal errors preserve `error_message` and `classification_output: ["ERROR"]` while adding structured error details. Aggregate metrics score successful and degraded classifications, exclude terminal errors, and report `total`, `scored`, `successful`, `degraded`, `failed`, and `complete` coverage fields.

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

Use `uv`; do not install packages globally. Python 3.12 is the recommended development version until the repository declares a supported range. The currently installed environment also imports successfully on Python 3.14.

From the repository root:

```bash
uv venv --python 3.12
uv pip install --python .venv/bin/python -r requirements.txt
```

Run commands through that environment without requiring shell activation:

```bash
uv run --python .venv/bin/python python src/CVE_expert_seq.py
```

Alternatively, activate it first:

```bash
source .venv/bin/activate
python src/CVE_expert_seq.py
```

Run project commands from the repository root. `config.py` resolves `.env` from that root even if the launch directory differs. Source imports still rely on `src` being placed on `sys.path` by running a file under `src/` or setting `PYTHONPATH=src` for module-based checks.

`requirements.txt` contains broad ranges and omits some directly imported packages that currently arrive transitively, including `langchain-core`, `langchain-text-splitters`, `numpy`, `requests`, and `tqdm`. It also includes packages unused by the selected live path. Do not silently regenerate dependencies or create a lockfile as part of an unrelated change.

The configured model identifiers resemble Hugging Face repository names, but the active code sends requests to OpenAI-compatible endpoints. It does not use the Hugging Face Hub CLI to download or serve these models.

## Runtime configuration

The full live pipeline expects these `.env` variables:

```dotenv
VAST_IP_PORT_MODEL=host:port
OPEN_BUTTON_TOKEN_MODEL=...
VAST_IP_PORT_EMBEDDING=host:port
OPEN_BUTTON_TOKEN_EMBEDDING=...
```

The code prepends `http://` and appends `/v1`; do not include a scheme or `/v1` in the current values. Chat and embedding endpoints/tokens are intentionally separate.

The replay path can avoid the embedding endpoint when a previous artifact already contains filtered chunks. `src/test.py` currently resumes from `nvd_filtered_chunks` and therefore only constructs chat-model clients, but its `LOG_FILE_PATH` must first be replaced or parameterized to point to a compatible local run artifact. Future replay work should support explicit, versioned resume stages rather than more hard-coded paths.

`validate_runtime_config(require_embedding=True)` checks all four settings before the live pipeline constructs clients. Replay calls it with `require_embedding=False`, so only chat settings are required. `RuntimeConfigurationError` reports missing variable names without their values.

Do not log credentials. When diagnosing configuration, report only whether each required setting is present, never its value.

## Running and verification

The offline regression suite uses standard-library `unittest`. `src/test.py` is still a manually configured replay experiment and must not be described as a unit test.

Safe local checks that do not call external services:

```bash
PYTHONPATH=src uv run --python .venv/bin/python python -m unittest discover -s tests -v
uv run --python .venv/bin/python python -m compileall -q src tests
uv pip check
git diff --check
```

Run live NVD, scraping, embedding, or LLM workflows only when the user explicitly authorizes the external calls and their likely cost/rate impact. A default live benchmark performs one sequential pass over 20 CVEs and can still make many reference, embedding, summarization, and classification calls.

## Development conventions

- Keep production behavior unchanged unless the task explicitly authorizes a behavior change.
- Prefer small, logically isolated commits. Separate documentation, tests, bug fixes, dependency changes, benchmark-data changes, and architectural refactors when practical.
- Before fixing a pipeline bug or changing the taxonomy/benchmark, explain the evidence, likely metric or runtime impact, and intended fix.
- Preserve flat-label behavior on `main` unless hierarchical support is explicitly requested.
- Treat scraped reference text as untrusted data when editing prompts or model calls.
- Preserve source provenance through retrieval, summarization, classification, and logs when adding new data flows.
- Avoid hard-coded absolute paths, run names, endpoint details, and concurrency values in new code.
- Do not use wildcard imports in new code. Add explicit types and stage-level validation when touching relevant code.
- Every commit should leave the offline `unittest` suite passing. Add regression coverage before or with a behavior fix.
- Never commit `.env`, runtime logs, model caches, downloaded weights, or credentials.
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
