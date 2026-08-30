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

`config.toml` contains only non-secret settings: complete endpoint URLs, model identifiers, stage parameters, and the evaluation output location. The application passes each `base_url` through unchanged, so it can point to any compatible remote service or local server.

The `[chat].api_key_env` and `[embedding].api_key_env` settings name environment variables; they do not contain credentials. Define those variables in the ignored repository-root `.env` file. With the names from the template:

```dotenv
CVEXPERT_CHAT_API_KEY=replace-with-your-chat-key
CVEXPERT_EMBEDDING_API_KEY=replace-with-your-embedding-key
```

The two TOML settings may name the same environment variable when one credential serves both endpoints. Never store an API key in either TOML file.

The loader rejects missing tables, unknown settings, invalid URLs and ranges, and missing credential-variable names before constructing clients. It reports variable names without revealing their values.

## Run

The active entry point evaluates the 20 CVEs in `CVE_TEST` once, in insertion order:

```bash
uv run python src/CVE_expert_seq.py
```

This is a live workflow: it contacts NVD, downloads external pages, and invokes the configured embedding and chat endpoints. It has no persistent cache, retry policy, or rate limiter yet. Review the likely request volume and service cost before running it.

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
