# AGENT_NOTES.md

Persistent working memory for CVExpert. Read this file with `AGENTS.md` before starting work. Update it when project understanding, decisions, findings, scope, progress, or open questions change. Never store credential values.

## Current status

- Last updated: 2026-08-29 (Europe/Rome)
- Active branch: `main`
- Linear code snapshot reviewed: `b32ccf5` (`Add NoRagClassifierNode`)
- Graph branch snapshot reviewed for comparison: `graphCVExpert` at `411baf6`
- Documentation commit completed: `c95e0f0` (`docs: add repository guidance for coding agents`)
- Current phase: repository documentation and technical review only
- Production code, dependencies, taxonomy, benchmark data, and runtime behavior have not been changed.
- Next decision: select and discuss the first reliability/bug-fix unit before editing production code.

## Durable user decisions

1. Work exclusively on the first, linear implementation on `main` after the initial two-branch review.
2. Treat code as authoritative and cross-check all documentation against it.
3. Maintain this file as a persistent second memory for understanding, decisions, findings, work state, and open questions.
4. Prefer more numerous, small, logically isolated commits. Documentation commits are authorized directly; explain and discuss bug fixes or larger behavior changes before implementation.
5. The desired long-term product shape is both:
   - a reusable classifier that can process arbitrary individual/batch CVEs; and
   - a separate, repeatable benchmark/evaluation harness.
6. The active linear taxonomy is flat: `CVE_TEST` refers to `LABELS_DESCRIPTIONS`. `VULNERABILITY_TREE` belongs to the graph experiment and is ignored by the active linear pipeline.
7. Preserve the option to support either flat or hierarchical taxonomies in the future, but keep the current flat behavior that matches the linear benchmark.
8. Intended flat-label semantics are evidence-backed multi-label classification: return each supported mechanism directly supported by evidence, and make `NONE` mutually exclusive. The existing fixture has not yet been re-audited against this intent.
9. Chat and embedding models use separate hosts and tokens. Embedding configuration can be avoided when resuming from a JSON artifact that already contains a later-stage result such as filtered chunks.
10. Future replay should resume from explicit named stages (for example, filtered chunks, summaries, or classification context), using a versioned artifact rather than a hard-coded one-off loader.

## Repository understanding

### What the current program actually is

Despite the README describing a general AI tool for CVE understanding, the active entry point is a benchmark script. `src/CVE_expert_seq.py` builds one LangChain `RunnableSequence`, then runs the 20 hard-coded `CVE_TEST` cases eight times through a `ThreadPoolExecutor`.

Each evaluation thread performs the entire live workflow independently:

```text
cve_id
  -> NVD description + ranked reference URLs
  -> fetched/extracted reference pages
  -> semantic chunks
  -> embedding-thresholded chunks
  -> LLM summaries per reference
  -> combined RAG context
  -> structured flat-label LLM classification
  -> per-CVE and aggregate micro metrics
  -> JSON run log
```

No acquisition, page, chunk, embedding, or summary cache is shared across the eight evaluations.

### Selected live components and defaults

- Entry point: `src/CVE_expert_seq.py`
- Benchmark cases: 20
- Evaluation threads/runs: 8
- Chat/classifier model: `openai/gpt-oss-20b`
- Summarizer model: `openai/gpt-oss-20b`
- Embedding model: `Qwen/Qwen3-Embedding-4B`
- Chat temperature: `0.2`
- Maximum successfully extracted reference pages: 10
- Chunker: `SemanticChunkerNode`, percentile threshold amount `25.0`
- Filter: `CosineFilterNode`, query `What type of vulnerability is it?`, threshold `0.6`
- Summarizer: `CVEAwareSummarizerNode`
- Classifier: `CVEClassifierNode`
- Output directory name is hard-coded as `logs/LOG_GPT_NORANDAware`, independent of the computed pipeline identifier.

### Stage state

`CVEClassifierState` documents a single dictionary that accumulates:

- `cve_id`
- `nvd_description`
- `nvd_url_references`
- `nvd_references_pages`
- `nvd_references_chunks`
- `nvd_filtered_chunks`
- `summaries`
- `rag`
- `cve_labels`
- optionally `labels_motivation` and `labels_confidence`

The `TypedDict` marks every field required, but real invocations begin with only `cve_id`. Stages shallow-copy the current dictionary and add their output.

### Replay experiment

`src/test.py` is not a test suite. It duplicates much of the benchmark runner, loads selected fields from an existing log with `StateFromFileLoader`, and then runs summarization, formatting, and a five-call self-consistency classifier. Its `LOG_FILE_PATH` is an absolute `/home/andyvale/...` path that does not match the current machine. The loader silently omits requested fields absent from a log entry.

Because this replay starts from `nvd_filtered_chunks`, it does not construct or call the embedding client. It still needs a chat endpoint/token and a compatible JSON log.

### Dependencies and environment

- Dependency declaration: only `requirements.txt`, with broad minimum versions.
- Missing project metadata: no `pyproject.toml`, declared Python range, lockfile, lint/type/test configuration, or CI.
- Several direct imports are undeclared and currently arrive transitively: `langchain-core`, `langchain-text-splitters`, `numpy`, `requests`, and `tqdm`.
- Several declared libraries are unused by the selected live path.
- `langchain-experimental` emitted a local deprecation warning stating that it is being sunset; the selected semantic chunker currently comes from that package.
- Local observation on 2026-08-29: `uv 0.11.26`, Python `3.14.6`, 101 installed packages, dependency check clean, and runtime imports successful.
- Local observation on 2026-08-29: the `.env` contains the chat host/token names but not the two embedding variable names required by the full live entry point. Values were not displayed. Recheck rather than assuming this remains true.

## Documentation inconsistencies

- `README.md` is only a short project motivation. It contains no setup, configuration, run, test, architecture, taxonomy, evaluation, or output documentation.
- The current README no longer embeds `imgs/system.png`; an earlier revision did.
- `imgs/system.png` is stale: it omits explicit chunking, NVD reference ranking, embeddings, benchmark parallelism, and evaluation metrics.
- Scraper documentation says references are randomly shuffled, but the current function does not shuffle them; it processes NVD-ranked order.
- Several stage docstrings call ordinary callable stages “LangGraph nodes” even though `main` uses LangChain sequencing.
- `src/test.py` is named like an automated test but is a manually configured experiment.
- `nvd_caller` documents raising HTTP errors, but catches every exception and returns fallback state instead.

## Two-branch review

### Linear `main`

`main` uses a flat taxonomy and a `RunnableSequence`. Prompts remain embedded inside summarizer/classifier classes. The active script executes the full live retrieval and classification path and catches most stage errors locally.

### `graphCVExpert`

The graph branch descends from the linear history, removes the sequential entry point, adds LangGraph entry points, changes the benchmark to hierarchical paths, externalizes prompts, and adds an iterative hierarchical classifier. Its current entry points replay a pre-existing log from a hard-coded absolute path rather than exercising the full NVD-to-classifier workflow.

Useful ideas that may be selectively ported to the linear implementation:

- prompts isolated in `src/Definitions/prompts.py`;
- local `random.Random` instances per evaluation;
- batched embedding/filter requests across references;
- batched summarization requests;
- retry/backoff around NVD HTTP work;
- explicit error propagation instead of silently predicting `NONE`;
- per-origin coordination for concurrent scraping;
- `zero_division=0` in metric calls.

Do not port these blindly. The graph branch also has material problems:

- `langgraph` is imported but not declared in its requirements file;
- entry points contain machine-specific paths and arbitrary log directory names;
- one hierarchy-validation graph can loop until the graph recursion limit if predictions stay invalid;
- its NVD retry predicate retries nearly every exception except HTTP 404, including errors that may not be transient;
- `asyncio.run` in a synchronous scraper wrapper is incompatible with callers that already own an event loop;
- task cancellation and rate limiting need stronger lifecycle handling;
- graph orchestration is unnecessary for the agreed linear direction.

## Prioritized findings

Priority meanings:

- **P0**: invalidates reliability or makes results look valid when the pipeline actually failed.
- **P1**: likely degrades classification quality, benchmark validity, or operational cost substantially.
- **P2**: maintainability, observability, performance, or reproducibility debt that should be addressed deliberately.

### P0 — Silent failures become ordinary predictions

Evidence:

- `nvd_caller` catches every exception and returns `nvd_description = "No description found"` with no references.
- summarizers catch each LLM failure, omit the affected summary, and continue.
- `CVEClassifierNode` and `CVENoRagClassifierNode` catch classification exceptions and return `cve_labels = ["NONE"]`.
- `run_evaluation` therefore often records a successful CVE instead of an error, even when a critical upstream/model stage failed.

Impact:

- Infrastructure/model failures are indistinguishable from a genuine “no supported category” result.
- Reliability cannot be measured from the output logs.
- Metrics can be biased and debugging becomes guesswork.

Approach:

- Define explicit stage error types and a run policy for retryable, skippable, and terminal failures.
- Reserve `NONE` for a successful evidence-based classification.
- Record stage/status/error metadata separately and include coverage/error rates in evaluation summaries.

### P0 — Full default execution creates an uncontrolled request burst

Evidence:

- Eight threads each query NVD for the same 20 CVEs: up to 160 NVD requests before considering retries.
- Every run also re-scrapes reference websites and repeats embeddings, summaries, and classifications.
- There is no NVD API key support, cross-thread limiter, response cache, or retry/backoff on `main`.
- Shuffling CVE order changes ordering but not request volume or rate.

Impact:

- Avoidable throttling/blocking, inconsistent data, high latency, unnecessary model cost, and load on third-party sites.
- Repeated evaluations confound model stochasticity with changing acquisition results.

Approach:

- Fetch and persist deterministic source/preprocessing artifacts once per CVE.
- Add API-key-aware NVD headers, bounded retry/backoff, and a shared rate limiter.
- Run repeated stochastic evaluation only from a pinned artifact stage.
- NVD documentation confirms that excessive access can trigger throttling/blocking and that API keys affect allowed volume: https://nvd.nist.gov/developers/request-an-api-key and https://nvd.nist.gov/general/FAQ-Sections/General-FAQs.

### P0 — “Cosine” filtering is only a dot product

Evidence:

- `CosineFilterNode` computes `np.dot(chunk_embeddings, query_embedding)`.
- Neither vector set is normalized by the node.
- Correctness therefore depends on an undocumented property of the embedding server/model.

Impact:

- Vector magnitude can dominate semantic direction.
- The fixed `0.6` threshold is not portable across providers/configurations and may admit or reject the wrong chunks.

Approach:

- L2-normalize both query and document matrices in the node or use a tested cosine-similarity implementation.
- Handle zero vectors and add deterministic unit tests with deliberately unnormalized embeddings.
- Recalibrate thresholds using the benchmark after fixing the math.

### P0 — Live configuration fails late and unclearly

Evidence:

- `config.py` loads relative `.env` values without validating them.
- The entry point interpolates missing hosts into strings such as `http://None/v1`.
- A missing embedding token currently raises during `OpenAIEmbeddings` client construction.
- Running outside the repository root can prevent `.env` discovery.

Impact:

- Failures occur after program startup with provider-specific messages rather than actionable configuration errors.

Approach:

- Introduce a typed settings object with mode-specific validation.
- Validate only the services needed for the selected resume stage.
- Resolve `.env` relative to the repository/config file or accept an explicit path.

### P0 — Evaluation coverage and failures are misreported

Evidence:

- Aggregate metrics include only CVEs appended after a nominally successful invocation.
- CVEs caught by `run_evaluation` are absent from aggregate scoring.
- Earlier stage/model errors converted to `NONE` are included as if classification succeeded.
- Individual prediction cleaning and grouped prediction handling are inconsistent.

Impact:

- A run with failures can appear better than a complete run.
- Scores from different runs may cover different samples and are not directly comparable.

Approach:

- Report requested, successful, failed, and scored sample counts.
- Define whether terminal failures score as incorrect or are reported separately, then apply one policy consistently.
- Use one validation/binarization path for individual and grouped metrics.

### P1 — Semantic chunking is unusually aggressive

Evidence:

- `SemanticChunkerNode` sets percentile threshold amount `25.0`.
- The installed `langchain_experimental` implementation defaults percentile mode to `95` and splits at distances above the selected percentile.
- At percentile 25, approximately the upper 75% of eligible boundaries can become breakpoints, subject to the input distribution.

Impact:

- Likely production of many small fragments, additional embedding work, loss of local context, and noisy summarization inputs.

Approach:

- Measure actual chunk counts/lengths and retrieved-label performance on cached pages.
- Compare recursive/Markdown chunking and calibrated semantic thresholds under a fixed evaluation artifact.
- Set explicit min/max chunk sizes and token budgets.

### P1 — Retrieval is generic, duplicated, and unbounded

Evidence:

- Every CVE uses the fixed query `What type of vulnerability is it?`.
- The filter query ignores `cve_id`, the NVD description, affected product, and taxonomy definitions.
- Semantic chunking embeds sentence windows, then filtering embeds the resulting chunks again.
- There is no top-k or global token cap for `CosineFilterNode`; every chunk above threshold survives.

Impact:

- Relevant CVE-specific mechanism evidence can be missed while generic vulnerability prose is retained.
- Cost and context size grow unpredictably.

Approach:

- Build target-specific retrieval from the NVD description/CVE metadata and explicit label evidence needs.
- Evaluate hybrid retrieval or a reranker before increasing model complexity.
- Reuse embeddings where the chunking strategy permits it and enforce per-source/global budgets.

### P1 — Summarization can remove or invent classification evidence

Evidence:

- The classifier receives summaries, not the selected source chunks.
- The summarizer is asked to bridge fragments into cohesive prose, which can turn implicit relationships into unsupported statements.
- The prompt says a source is related only when it explicitly discusses the CVE ID; useful vendor pages may describe the exact flaw without repeating the ID.
- Per-reference failures simply remove evidence.

Impact:

- False negatives from discarded references and false positives from summary hallucinations.
- It is hard to audit which source text actually supports a label.

Approach:

- Replace free-form compression with structured evidence extraction: source ID, candidate label/mechanism, evidence span, and concise interpretation.
- Preserve selected source text or hashes alongside derived evidence.
- Consider classifying directly from budgeted chunks and use summarization only when proven beneficial by an ablation.

### P1 — External page content is untrusted prompt input

Evidence:

- Arbitrary extracted web text is interpolated directly into an instruction prompt.
- Prompts do not explicitly treat page content as untrusted data or defend instruction boundaries.

Impact:

- A referenced page can contain prompt-injection text that alters summarization or downstream classification.

Approach:

- Make instruction/data boundaries explicit, state that source instructions must be ignored, retain structured output validation, and add adversarial prompt-injection fixtures.
- Validate URLs/content types/response sizes before processing.

### P1 — Useful structured vulnerability evidence is ignored

Evidence:

- NVD handling keeps only the first description and external references.
- It does not explicitly select the English description.
- CWE/weakness, affected product/version, CVSS, and other structured fields are not included in retrieval or classification context.

Impact:

- The pipeline performs expensive web/LLM work while omitting fields that can directly identify vulnerability mechanisms and disambiguate products.

Approach:

- Normalize a richer source record before scraping.
- Prefer structured evidence as grounding, while treating CWE mappings as evidence rather than infallible labels.

### P1 — Classifier output invariants are incomplete

Evidence:

- The JSON schema has no `uniqueItems` constraint.
- It permits `NONE` alongside real labels.
- Basic classifier output contains labels only, with no evidence, confidence, or provenance.
- The self-consistency experiment returns every label seen at least once across five calls; it calculates frequency but applies no acceptance threshold.

Impact:

- Invalid combinations, duplicates, unauditable predictions, and reduced precision in the self-consistency path.

Approach:

- Normalize/deduplicate outputs and enforce `NONE` exclusivity.
- Require evidence references for every selected label.
- If self-consistency is retained, define and validate a frequency threshold and failure policy.

### P1 — Benchmark coverage is too weak for optimization

Observed benchmark facts:

- 20 CVEs, all with at least one non-`NONE` expected label.
- `InputValidation` appears in 17/20 cases and `AccessControl` in 11/20.
- `SQLi`, `CSRF`, and `ResourceExhaustion` have zero expected examples.
- Several labels have only one example.
- The `CVE-2025-59145` comment says the taxonomy does not cover the supply-chain compromise and that `NONE` is appropriate, but the expected labels are `CodeInjection` and `XSS`.
- Many examples are famous CVEs likely known to general-purpose models, so CVE-ID memorization can mask retrieval quality.

Impact:

- Aggregate micro-F1 is dominated by common labels.
- Per-label behavior and `NONE` handling cannot be validated.
- Prompt/model changes can overfit a tiny, contaminated benchmark.

Approach:

- First document and re-audit annotation rules against `LABELS_DESCRIPTIONS` without silently changing expected labels.
- Add negative/unsupported cases and balanced coverage for every label.
- Track per-label precision/recall/F1, exact match, sample-F1, Hamming loss, coverage, latency, and cost.
- Separate development and held-out cases; include newer/less-famous CVEs and optionally mask the CVE ID in retrieval ablations.

### P2 — Reproducibility and cross-run analysis are limited

Evidence:

- Threads share the global `random` module after one `random.seed(42)` call; interleaving can change sampling order.
- Acquisition results can change between repeated evaluations.
- The script does not compute mean, standard deviation, confidence interval, label stability, or aggregate cost across the eight run files.
- Run metadata says `RUN_N + 1` while filenames are zero-based.

Approach:

- Use a local RNG per run and record seeds.
- Evaluate repetitions from the same versioned input artifact.
- Add a cross-run report with variability and coverage.

### P2 — Work is sequential inside each CVE but over-parallelized across full runs

Evidence:

- Scraping is sequential per CVE.
- Filtering sends one embedding request per reference.
- Summarization sends one LLM request per reference.
- Eight complete pipelines run concurrently and share model/pipeline objects.

Impact:

- Poor batching efficiency combined with high uncontrolled external concurrency.

Approach:

- Make concurrency explicit per external service, with independent bounded limits.
- Batch compatible embeddings/model calls.
- Prefer parallelism across cached CVEs/stages rather than eight redundant acquisition runs.

### P2 — Logging is expensive and weakly identified

Evidence:

- The entire growing JSON document is rewritten after every CVE and once again at completion.
- Writes are not atomic, so interruption can leave malformed JSON.
- Directory names are hard-coded and can misdescribe the active pipeline.
- The state/log retains full pages, chunks, filtered chunks, summaries, and RAG, creating large artifacts without schema/version/hash metadata.

Approach:

- Define a versioned artifact schema with pipeline/config hashes and timestamps.
- Use atomic writes or append-only per-CVE records plus a final manifest.
- Separate reusable stage artifacts from concise evaluation results.

### P2 — Entry points and configuration are tightly coupled

Evidence:

- Models, thresholds, run counts, endpoints, and log directory names are code constants.
- Pipeline construction lives under `if __name__ == "__main__"` and is not exposed as a reusable factory.
- Benchmark execution, external clients, orchestration, scoring, and persistence share one module.
- `src/test.py` duplicates runner/logging code.

Approach:

- Introduce typed configuration and explicit pipeline/runner factories.
- Provide separate classify and benchmark commands.
- Keep resume-stage selection an input rather than a separate copied script.

### P2 — Structure and dependency hygiene impede safe change

Evidence:

- Linear stages live under `Graph/Nodes` and retain graph-specific names/docstrings.
- Prompts are embedded in large classes, making versioning and prompt-only tests difficult.
- The entry points use wildcard evaluator imports.
- Broad exceptions obscure expected failure modes.
- There are no unit, integration, contract, or snapshot tests.
- Dependencies are unpinned and not reproducibly locked.

Approach:

- Add tests before moving modules.
- Externalize/version prompts and schemas.
- Gradually introduce a neutral pipeline namespace with compatibility imports if a move is justified.
- Declare direct dependencies and a Python range, then create a reviewed lockfile in a dedicated dependency commit.

## Recommended improvement sequence

Do not start all of these at once. Keep each unit reviewable and measure behavior after each quality-affecting change.

1. **Baseline and contracts**
   - Add fast unit tests for metrics, NVD parsing/ranking, chunk/filter behavior, formatter output, classifier normalization, and state loading using fakes/fixtures.
   - Define stage status/error semantics and a versioned artifact manifest.
   - Record the unchanged current benchmark as a baseline before correcting annotations.
2. **Configuration and error correctness**
   - Add typed, mode-aware settings and fail-fast validation.
   - Stop converting operational errors to `NONE`; report coverage and failures.
   - Enforce classifier output invariants.
3. **Reusable pipeline and benchmark split**
   - Extract model/stage factories and a reusable single/batch classify API.
   - Build a separate benchmark runner on top.
   - Replace `src/test.py` with named resume-stage behavior.
4. **Reliable acquisition and artifacts**
   - Add NVD key support, bounded retry/backoff, shared rate limiting, English-description selection, richer structured fields, caching, and provenance.
   - Add safe bounded scraping with content/size validation.
5. **Retrieval and evidence quality experiments**
   - Fix cosine math first.
   - Evaluate chunkers, target-specific retrieval, top-k/token limits, batching, and structured evidence extraction one variable at a time.
   - Add prompt-injection tests and preserve source citations.
6. **Benchmark audit and reporting**
   - Resolve annotation contradictions with explicit rules.
   - Expand label/negative coverage and add held-out evaluation.
   - Add per-label, exact-match, stability, latency, and cost reporting.
7. **Only then consider larger structural cleanup**
   - Neutral module names, packaging, prompt modules, dependency locking, CI, and optional taxonomy interfaces.
   - Do not adopt LangGraph merely to reuse graph-branch improvements.

## Candidate first change units

These are proposals, not authorization to edit production code:

1. Unit tests for `CosineFilterNode`, evaluators, formatter, and classifier normalization using fake embeddings/models.
2. Correct cosine normalization plus threshold-regression tests.
3. Explicit error/status model that separates operational failure from `NONE`.
4. Typed configuration validation with separate requirements for live and replay modes.
5. Versioned stage-artifact schema and parameterized replay loader.

The first two units are narrow and high-value, but changing cosine behavior can change benchmark results and must be discussed before implementation.

## Open questions for future work

- What public interface should the reusable classifier expose first: Python API, CLI, or both?
- Is an NVD API key available for development/production, and what request-rate policy should be enforced?
- What concurrency and cost limits apply to each chat and embedding endpoint?
- Which stages and fields must version 1 of the replay artifact support?
- Should cached source pages be stored in repository-external artifacts, logs, or a dedicated cache directory?
- Who will approve benchmark annotation changes, especially ambiguous mechanism-versus-impact cases?
- What minimum evidence format is required for a label to be accepted: source ID, quote/span, URL, confidence, or all of these?
- What Python version should become the declared project baseline?

## Work log

### 2026-08-29 — Initial exploration and review

- Read the current README and every Python file on `main`.
- Inspected branch history and compared `main` with `graphCVExpert` without checking out or modifying the graph branch.
- Reviewed graph entry points, taxonomy, prompts, changed nodes, and graph-specific `AGENTS.md`.
- Inspected `imgs/system.png` and README history.
- Confirmed the worktree was initially clean on `main` at `b32ccf5`.
- Confirmed `uv`/Python environment details, import compatibility, and dependency consistency.
- Confirmed Python compilation succeeds and evaluator smoke output is correct.
- Confirmed automated unittest discovery finds zero tests.
- Compiled/imported a temporary archive of `graphCVExpert` successfully.
- Did not call NVD, fetch reference pages, invoke embedding/chat models, or expose credentials.
- Created and committed `AGENTS.md` as `c95e0f0`.
- Created this persistent review/memory file as the second documentation unit.

## Notes maintenance checklist

When resuming work:

1. Read `AGENTS.md` and this file.
2. Check the current branch, commit, and worktree before editing.
3. Revalidate transient environment observations instead of assuming they remain true.
4. Record new user decisions immediately.
5. Move completed work into the dated work log and update “Current status.”
6. Add newly discovered risks with evidence, impact, and proposed approach.
7. Remove or correct claims disproved by code/tests.
8. Never record secret values, private tokens, or sensitive log content.
