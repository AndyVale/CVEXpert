# AGENTS.md

This file applies to the entire repository. Read it together with `AGENT_NOTES.md` before changing the project. Treat the code as the source of truth when this file or `README.md` disagrees with the implementation.

## Project direction

CVExpert classifies CVEs into project-defined security labels by collecting NVD data, extracting external references, filtering technical evidence, and asking an LLM for a structured multi-label result.

- Work on `main`, which contains the active linear LangChain pipeline.
- `graphCVExpert` is a historical/reference branch containing a LangGraph and hierarchical-label experiment. Inspect it for ideas when useful, but do not base new work on it or introduce LangGraph into `main` unless the user explicitly requests that change.
- The active taxonomy is selected from JSON through `[fixtures].taxonomy_file`. The optional expected-classification JSON is used only in `--benchmark` mode.
- The linear classifier accepts flat and hierarchical taxonomies with `most_specific` semantics. The historical graph branch remains reference material only.
- The intended longer-term shape is a reusable CVE-classification pipeline plus a separate benchmark runner. The current code has not yet been separated that way.

## Repository map

- `README.md`: user-facing setup, configuration, execution, architecture, and verification guidance.
- `pyproject.toml`: authoritative project metadata, Python range, and direct dependencies. The project is deliberately non-packaged (`tool.uv.package = false`) while its entry points remain scripts.
- `uv.lock`: committed complete dependency resolution. `requirements.txt` has been removed.
- `config.example.toml`: the only tracked configuration file; a provider-neutral template with credential placeholders.
- `config.toml` and `config.*.toml`: ignored local runtime configurations copied from the template. They contain real endpoint credentials and must never be committed; `.gitignore` explicitly re-allows only `config.example.toml`.
- `src/CVE_expert_seq.py`: active entry point for explicit-CVE classification and benchmark runs through the full live linear pipeline.
- `src/Definitions/config.py`: typed TOML settings, strict validation, repository-root path resolution, and secret-safe object representations.
- `src/Definitions/fixtures.py`: JSON taxonomy and benchmark loading, canonical fingerprints, and hierarchy validation.
- `fixtures/{flat,hierarchical,hybrid}/`: three taxonomy and 50-case expected-classification pairs.
- `src/Graph/state.py`: shared `CVEClassifierState` `TypedDict`.
- `src/Graph/errors.py`: terminal `PipelineStageError` and recoverable `PipelineWarning` records.
- `src/Graph/request_pacing.py`: thread-safe minimum-interval pacing shared across synchronous chat, embedding, and NVD requests.
- `src/Graph/reporting.py`: centralized tqdm-safe console logging, ANSI severity colors, concise diagnostics, redaction, and the verbose runtime-configuration table.
- `src/Graph/stage_timing.py`: callback that records top-level linear stage durations without storing prompts or responses.
- `src/Graph/Nodes/`: reusable pipeline stages. The `Graph` name and several LangGraph-oriented docstrings are historical; these objects are also used as ordinary LangChain callables.
- `tests/`: standard-library `unittest` regression suite. Tests use fakes and must remain offline.
- `imgs/system.png`: an older high-level architecture diagram that omits some current stages.
- `logs/`: ignored runtime artifacts; full runs rewrite one JSON file per evaluation after every CVE.

## Active linear pipeline

`src/CVE_expert_seq.py` constructs a `RunnableSequence` with these stages:

1. `nvd_caller` requests the CVE description and reference URLs from NVD, then ranks references by NVD tags.
2. `extract_md_trafilatura` downloads reference pages sequentially and extracts Markdown, stopping after the configured `[references].max_pages` successful pages.
3. `SemanticChunkerNode` narrows exceptionally large multi-CVE indexes to context around the requested CVE, then splits pages using an embedding-backed semantic splitter. Full extracted pages remain in state.
4. `CosineFilterNode` embeds chunks and retains chunks above a relevance threshold.
5. `CVEAwareSummarizerNode` asks the chat model for one structured summary per retained reference.
6. `formatter` combines the NVD description and summaries into the classifier context stored as `rag`.
7. `CVEClassifierNode` evaluates the configured labels in token-bounded groups, removes selected ancestors of selected descendants, and returns `NONE` only when no group selects a label.
8. `run_evaluation` compares predictions with the selected JSON cases and writes metrics; `run_classification` handles explicit CVE IDs without ground-truth scoring.

`main()` requires explicit CVE IDs, loads and validates `config.toml` and the selected JSON before client construction, builds the pipeline once, then processes the requested CVEs in CLI order. With `--benchmark`, every requested ID must exist in the expected-classification JSON and only those cases are scored; unrequested JSON cases are ignored. The tracked template sets both chat temperatures to `0.0`; a local configuration can change them. Temperature zero reduces avoidable variability but cannot guarantee provider-level determinism. The live run is sequential and still has no NVD/page/model cache, acquisition retry policy, token-based limiter, or batching. Chat, embedding, and NVD requests have separate configurable minimum intervals; summarization and classification share the chat pacer, semantic chunking and filtering share the embedding pacer, and all CVEs share one NVD pacer.

The CLI requires positional CVE IDs and accepts optional `--benchmark` and `-v`/`--verbose`. Normal mode shows lifecycle messages, tqdm progress, errors, and completion; verbose mode adds recoverable warnings, a secret-safe configuration table before client construction, and stage-level count summaries. Verbose recoverable warnings are printed immediately through `tqdm.write()` and remain recorded in JSON in both modes. Interactive warnings are yellow and errors red; `NO_COLOR` disables ANSI output. Top-level failures are concise and return a nonzero CLI status without a traceback wall.

Terminal NVD, filtering, formatter-precondition, or classifier failures raise `PipelineStageError`; they must never be converted to `NONE`. A successful, validated model response may return `["NONE"]`. Individual reference scrape, chunk, or summary failures are recoverable: stages keep usable references, append `PipelineWarning` records, and the runner reports the CVE as `degraded`.

`CosineFilterNode` requests and caches its query embedding during the first CVE with chunks. A failed request becomes a per-CVE filter error, leaving later CVEs able to retry. HTML gateway error bodies are summarized in console diagnostics, with the stage and CVE shown first.

The template writes benchmark results to `logs/RUN_0.json`; classification-only runs write distinct `logs/CLASSIFY_*.json` files. `[evaluation].log_directory` and benchmark `run_number` are configurable. The former `logs/LOG_GPT_NORANDAware/` directory may still contain historical ignored artifacts and must not be deleted automatically. Per-CVE status is `success`, `degraded`, or `error`. Terminal errors preserve `error_message` and `classification_output: ["ERROR"]` while adding structured error details. Benchmark metrics score successful and degraded requested CVEs, exclude terminal errors, and report exact-match accuracy, micro precision/recall/F1, and `total`, `scored`, `successful`, `degraded`, `failed`, and `complete` coverage fields. Classification-only artifacts omit scores and expected labels.

Live `RunnableSequence` runs also record per-CVE `stage_timings` in seconds, including a failed stage. These wall-clock durations include endpoint latency and configured pacing; timing callbacks never persist stage input or output content. When chunking narrows a broad multi-CVE index, `reference_focus` records only its original and focused character counts; the complete extracted page remains in `nvd_references_pages`.

### State fields

Stages shallow-copy and extend a dictionary matching `CVEClassifierState`. In normal order, fields appear as follows:

- Input: `cve_id`
- NVD: `nvd_description`, `nvd_url_references`
- Scraping: `nvd_references_pages`
- Chunking: `nvd_references_chunks`
- Broad-index focusing, when applied: `reference_focus`
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
uv run python src/CVE_expert_seq.py --benchmark CVE-2021-27103
uv run python src/CVE_expert_seq.py CVE-2021-27103 --verbose
```

Alternatively, activate it first:

```bash
source .venv/bin/activate
python src/CVE_expert_seq.py CVE-2021-27103
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

`config.toml` stores the complete local configuration, including real `[chat].api_key` and `[embedding].api_key` values. Its supported tables are `[chat]`, `[embedding]`, `[nvd]`, `[references]`, `[semantic_chunker]`, `[cosine_filter]`, `[fixtures]`, `[classification]`, and `[evaluation]`. Complete chat and embedding `base_url` values are passed through unchanged; do not rely on implicit scheme or `/v1` manipulation. The configuration is provider-neutral within the OpenAI-compatible API contract. No `.env` file is loaded or required.

`[fixtures].taxonomy_file` is mandatory and `[fixtures].expected_classification_file` is optional. Both resolve from the repository root; the latter is loaded only for `--benchmark`. `[classification].max_input_tokens` limits the classifier's approximate rendered input estimate to `ceil(1.2 × UTF-8 bytes ÷ 3)` per label group. It is not a provider token guarantee.

`[chat].request_delay_seconds`, `[embedding].request_delay_seconds`, and `[nvd].request_delay_seconds` are independent minimum intervals between synchronous outbound requests. Use slightly more than the provider window divided by its request allowance for quota headroom; `0.0` disables pacing. Chat and embedding SDK retries are paced; NVD currently has no retry loop. The active NVD request does not include an API key, so the tracked keyless example uses `6.1` seconds for the public five-requests-per-30-seconds allowance. These settings do not control tokens per minute. `[embedding].check_embedding_ctx_length = false` makes LangChain send raw text rather than OpenAI token arrays, improving compatibility at the cost of automatic input-length splitting.

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

Run live NVD, scraping, embedding, or LLM workflows only when the user explicitly authorizes the external calls and their likely cost/rate impact. The tracked example benchmark contains 50 CVEs; larger taxonomies can require several classifier calls per CVE.

## Development conventions

- Keep production behavior unchanged unless the task explicitly authorizes a behavior change.
- Prefer logically cohesive commits. They may be moderately large when one change spans its tests and integration, but keep configuration/runtime work, dependencies, documentation, benchmark data, and unrelated architectural changes separate when practical.
- Before fixing a pipeline bug or changing the taxonomy/benchmark, explain the evidence, likely metric or runtime impact, and intended fix.
- Preserve the selected taxonomy's `most_specific` hierarchy semantics and reject mismatched benchmark fingerprints.
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
