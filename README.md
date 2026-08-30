# CVExpert

CVExpert is an evidence-backed, multi-label CVE classification pipeline. It retrieves a CVE from NVD, extracts technical evidence from ranked references, filters and summarizes that evidence, and asks an LLM to select labels from the repository's flat security taxonomy.

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

`[chat].request_delay_seconds` and `[embedding].request_delay_seconds` set the minimum interval between consecutive outbound HTTP attempts for each service. Use a value slightly greater than `60 / requests-per-minute`; set it to `0.0` only when pacing is unnecessary. Chat pacing is shared by summarization and classification, while embedding pacing is shared by semantic chunking and cosine filtering. SDK retries are paced too. This controls request frequency only—it does not enforce token-per-minute quotas.

`[embedding].check_embedding_ctx_length` controls LangChain's OpenAI-specific tokenization and automatic length splitting. `false` sends raw text, which is accepted by a broader range of OpenAI-compatible endpoints; callers must then keep inputs within the selected model's limits.

## Run

The active entry point evaluates the 20 CVEs in `CVE_TEST` once, in insertion order:

```bash
uv run python src/CVE_expert_seq.py
```

This is a live workflow: it contacts NVD, downloads external pages, and invokes the configured embedding and chat endpoints. Model requests have configurable minimum-interval pacing, but there is no persistent cache, acquisition retry policy, or token-per-minute limiter. Review the likely request volume and service cost before running it.

By default, the template writes `logs/LOG_GPT_NORANDAware/RUN_0.json`. The log directory and run number are configurable in `[evaluation]`.

## Pipeline

```text
CVE ID
  -> NVD description and ranked references
  -> extracted reference pages
  -> semantic chunks
  -> cosine-filtered evidence
  -> per-reference summaries
  -> formatted classification context
  -> validated flat labels
  -> per-CVE and aggregate evaluation results
```

An individual reference scrape, chunk, or summary failure produces a warning and a `degraded` result when usable evidence remains. NVD, embedding/filter, formatting-precondition, and classifier failures produce an explicit `error`; operational failures are never converted into a valid-looking `NONE` label.

## Offline verification

The automated suite uses standard-library `unittest` and fakes all external services:

```bash
PYTHONPATH=src uv run python -m unittest discover -s tests -v
uv run python -m compileall -q src tests
uv lock --check
uv pip check
git diff --check
```
