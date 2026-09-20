# CVExpert

CVExpert is an evidence-backed, multi-label CVE classification pipeline. It retrieves a CVE from NVD, extracts technical evidence from ranked references, filters and summarizes that evidence, and asks an LLM to select labels from a configured JSON taxonomy.

The active implementation on `main` is a linear LangChain pipeline. The `graphCVExpert` branch is retained only as a historical LangGraph experiment.

## Requirements

- Python 3.12 or newer
- [uv](https://docs.astral.sh/uv/)
- OpenAI-compatible chat and embedding endpoints

Install the locked dependency set from the repository root:

```bash
uv sync --python 3.12
```

`pyproject.toml` declares the direct dependencies and supported Python version. `uv.lock` pins the complete environment. There is no `requirements.txt`.

## Configuration

Copy the tracked template to the ignored local configuration file:

```bash
cp config.example.toml config.toml
```

`config.toml` contains complete endpoint URLs, API keys, model identifiers, stage parameters, and the evaluation output location. The application passes each `base_url` through unchanged, so it can point to any compatible remote service or local server. No `.env` file is required.

Replace the `[chat].api_key` and `[embedding].api_key` placeholders in your local copy. The two values may be identical when one credential serves both endpoints. The real `config.toml` and local variants such as `config.production.toml` are ignored by Git; only `config.example.toml`, which must contain placeholders rather than real credentials, is tracked. Never force-add a real configuration file.

The loader rejects missing tables, unknown settings, empty API keys, and invalid URLs or ranges before constructing clients. Secret fields are excluded from the configuration object's representation to reduce accidental logging.

`[fixtures].taxonomy_file` selects the required taxonomy JSON. `[fixtures].expected_classification_file` is optional and is read only with `--benchmark`. Paths are resolved from the repository root. Three pairs are provided in `fixtures/flat`, `fixtures/hierarchical`, and `fixtures/hybrid`; select both paths from the same folder when benchmarking. Their label IDs, descriptions, parent links, benchmark rationales, sources, and fingerprints are preserved. The benchmark loader checks that the selected case file matches the taxonomy fingerprint.

`[classification].max_input_tokens` sets an approximate input budget for each classifier call. The classifier estimates rendered prompt and schema tokens using `ceil(1.2 × UTF-8 bytes ÷ 3)` and splits labels into groups when needed. This estimate is provider-neutral and does not guarantee a provider's actual token count. If the evidence cannot fit with even one label, that CVE ends with a classifier error rather than silently dropping evidence.

`[chat].request_delay_seconds`, `[embedding].request_delay_seconds`, and `[nvd].request_delay_seconds` set independent minimum intervals between consecutive outbound attempts. Chat pacing is shared by summarization and classification, embedding pacing is shared by semantic chunking and cosine filtering, and one NVD pacer is shared across the run. SDK retries are disabled: `[resilience]` and each stage's `max_attempts` provide the bounded, observable retry policy for transient network errors, HTTP 408/409/425/429, and 5xx responses. `Retry-After` is honored only within the configured delay and remaining deadline.

The optional `[nvd].api_key` enables authenticated NVD access. The tracked template leaves it commented and uses `6.1` seconds to add slight headroom over the public limit of five requests per rolling 30-second window.

`[references]` bounds redirects, connect/read timeouts, downloaded bytes, and extracted characters. Reference URLs must use credential-free HTTP(S), and each initial or redirected host must resolve only to public addresses. Only supported textual content types are accepted. `[semantic_chunker]` caps chunks per reference and CVE; `[summarization]` and `[classification]` cap estimated input and generated output tokens.

`[budgets]` enforces request, estimated/provider token, and monotonic wall-clock limits per CVE and run. Every external attempt counts, including retries, redirects, and structured-output repairs. A CVE budget failure is terminal for that CVE; run exhaustion records untouched remaining CVEs as budget errors without contacting external services.

`[embedding].check_embedding_ctx_length` controls LangChain's OpenAI-specific tokenization and automatic length splitting. `false` sends raw text, which is accepted by a broader range of OpenAI-compatible endpoints; callers must then keep inputs within the selected model's limits.

## Run

Classify one or more CVEs without ground truth or scoring:

```bash
uv run python src/CVE_expert_seq.py CVE-2021-27103 CVE-2024-27443
```

Add `--benchmark` to score only those CVEs against the configured expected-classification JSON:

```bash
uv run python src/CVE_expert_seq.py --benchmark CVE-2021-27103 CVE-2024-27443
```

At least one CVE ID is required in either mode. With `--benchmark`, every requested CVE must appear in the expected-classification file; otherwise setup fails before any live requests. Other cases in that file may be omitted. Results follow command-line order, and benchmark coverage and scores include only requested CVEs. Accuracy means the fraction of scored CVEs whose complete label set matches exactly; precision, recall, and F1 use micro averaging. At completion, benchmark mode prints an aligned table containing each CVE's status, expected and predicted labels, per-CVE metrics, aggregate metrics, and coverage. Failed CVEs remain visible with unavailable metrics shown as `—`. Classification-only mode does not print a score table. Add `-v` or `--verbose` for recoverable warnings, a safe configuration table, and stage-level summaries. Normal output includes run and CVE lifecycle messages, progress bars, terminal errors, and completion.

Console messages are written through `tqdm`, so verbose warnings and errors do not corrupt active progress bars. Warnings are yellow and errors are red in an interactive terminal. Set the standard `NO_COLOR` environment variable to disable ANSI colors. Technical diagnostics are shortened to one line, and configured API keys are redacted; the configuration table reports credentials only as `configured`. Recoverable warnings remain recorded in the JSON artifact even when normal mode does not print them.

This is a live workflow: it contacts NVD, downloads external pages, and invokes the configured embedding and chat endpoints. Requests have bounded retries, explicit timeouts, pacing, and run/CVE budgets, but there is no persistent cache or provider token-per-minute scheduler. Review the likely request volume and service cost before running it.

Every run selects a new artifact name. Benchmark files use `logs/RUN_<number>_<UTC timestamp>_<UUID prefix>.json`; classification files use the analogous `logs/CLASSIFY_<UTC timestamp>_<UUID prefix>.json`. Existing artifacts, including historical `logs/RUN_0.json`, are never selected as a new run target. Checkpoints are written to a same-directory temporary file, flushed, synchronized, and atomically replaced. Classification artifacts omit expected labels and scores; benchmark artifacts retain each case's rationale and sources.

Artifact schema version 1 records a UUID, zero-based benchmark run number, UTC start/completion times, monotonic durations, pipeline structure, taxonomy and prompt/schema versions, Git revision/dirty state, direct dependency versions, and a secret-free configuration fingerprint. Each CVE includes safe request-attempt telemetry and aggregate request, retry, repair, token, pacing, and latency totals. Telemetry retains provider request IDs and selected rate-limit headers when available, but never prompts, responses, credentials, or raw exception messages.

Each CVE entry records `stage_timings` for the live linear pipeline, including a stage that failed. Durations are wall-clock seconds and include service latency and request pacing; they are useful for locating slow stages but do not by themselves separate server time from waiting.

Before semantic chunking, a reference of at least 50,000 characters that mentions at least 100 distinct CVE IDs is treated as a broad vulnerability index. When it contains the requested CVE, chunking uses 2,000 characters of context on either side of each matching identifier. The complete extracted page remains in the log, and `reference_focus` records the original and focused character counts. Target-specific advisories and broad indexes without the requested CVE are left unchanged.

## Pipeline

```text
CVE ID
  -> NVD description and ranked references
  -> extracted reference pages
  -> semantic chunks
  -> cosine-filtered evidence
  -> per-reference summaries
  -> formatted classification context
  -> validated labels from the selected taxonomy
  -> per-CVE results, with scores in benchmark mode
```

The summarizer uses root-label descriptions for broad guidance. The classifier evaluates every label across one or more calls, includes each label's ancestors as context, and retains the most specific supported labels. It returns `NONE` only when no group selects a label. The flat, hierarchical, and hybrid fixtures all use the same linear pipeline; larger sets can require more classifier calls per CVE.

An individual reference scrape, chunk, filter, or summary failure produces a warning and a `degraded` result when usable evidence remains. Query-embedding failure, loss of every non-empty reference during filtering, budget exhaustion, NVD failure, formatting-precondition failure, or classifier failure produces an explicit `error`; operational failures are never converted into a valid-looking `NONE` label. Malformed structured output receives one corrective request. A second malformed summary skips that reference, while a second malformed classification remains terminal.

The filter obtains its query embedding during the first CVE that has chunks to filter. If that request fails, the failure is logged for that CVE and later CVEs can retry it. Console diagnostics keep the stage and CVE visible and summarize HTML gateway errors without printing the page body.

## Offline verification

The automated suite uses standard-library `unittest` and fakes all external services:

```bash
PYTHONPATH=src uv run python -m unittest discover -s tests -v
uv run python -m compileall -q src tests
uv lock --check
uv pip check
git diff --check
```

See [IMPLEMENTATION_REPORT.md](IMPLEMENTATION_REPORT.md) for the complete JSON-fixture migration, live debugger investigation, timing results, and remaining bottlenecks.
