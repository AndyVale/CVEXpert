# AGENT_NOTES.md

Persistent working memory for CVExpert. Read this file with `AGENTS.md` before starting work. Update it when project understanding, decisions, findings, scope, progress, or open questions change. Never store credential values.

## Current status

- Last updated: 2026-08-30 (Europe/Rome)
- Active branch: `main`
- Linear code snapshot includes the direct-TOML credential migration documented in the 2026-08-30 work log below.
- Graph branch snapshot reviewed for comparison: `graphCVExpert` at `411baf6`
- Documentation commit completed: `c95e0f0` (`docs: add repository guidance for coding agents`)
- Initial review/memory commit completed: `bf12e38` (`docs: add persistent agent notes and pipeline review`)
- First reliability batch implemented through `9a3a704` (`fix: compute true cosine similarity`)
- Model request pacing implemented in `d023bae` (`feat: pace model endpoint requests`).
- Current phase: configurable NVD request pacing is committed in `67f0641`; the 20-case `CVE_TEST` annotation audit is implemented and verified locally.
- The flat taxonomy itself, prompts, pipeline stage order, and artifact shape remain unchanged. `CVE_TEST` values and evidence comments have been re-audited; former hard-coded model/stage/evaluation values are validated local TOML settings.

## Durable user decisions

1. Work exclusively on the first, linear implementation on `main` after the initial two-branch review.
2. Treat code as authoritative and cross-check all documentation against it.
3. Maintain this file as a persistent second memory for understanding, decisions, findings, work state, and open questions.
4. Prefer logically cohesive commits. Commits may be larger when a change naturally spans tests and integration, while unrelated configuration, dependency, documentation, benchmark, and architectural work should remain separated. Explain and discuss bug fixes or larger behavior changes before implementation.
5. The desired long-term product shape is both:
   - a reusable classifier that can process arbitrary individual/batch CVEs; and
   - a separate, repeatable benchmark/evaluation harness.
6. The active linear taxonomy is flat: `CVE_TEST` refers to `LABELS_DESCRIPTIONS`. `VULNERABILITY_TREE` belongs to the graph experiment and is ignored by the active linear pipeline.
7. Preserve the option to support either flat or hierarchical taxonomies in the future, but keep the current flat behavior that matches the linear benchmark.
8. Intended flat-label semantics are evidence-backed multi-label classification: return every matching mechanism directly supported by evidence, and make `NONE` mutually exclusive. RCE alone is not CodeInjection, unauthenticated reach alone is not AccessControl, and a downstream impact or companion CVE's mechanism is not attributed to the CVE being classified.
9. Chat and embedding clients use independently configurable complete OpenAI-compatible base URLs, model identifiers, and credential-variable names. They may share a URL or credential when appropriate. Embedding credential validation can be avoided when resuming from a JSON artifact that already contains a later-stage result such as filtered chunks.
10. Future replay should resume from explicit named stages (for example, filtered chunks, summaries, or classification context), using a versioned artifact rather than a hard-coded one-off loader.
11. Operational/model failure is not a classification. `NONE` is valid only after a successful, validated classifier response.
12. Individual reference scrape, chunk, and summary failures are recoverable and make a result `degraded`; NVD, filtering, formatter-precondition, and classifier failures are terminal for that CVE.
13. The old eight-run benchmark did not calculate an average. It has been replaced with one insertion-order run. The tracked TOML template keeps temperature `0.0` for summarizer and classifier, though local configuration can override it; provider/runtime behavior may still vary.
14. Partial-run metrics exclude terminal errors but must report coverage and `complete: false`; degraded classifications remain scored.
15. `config.toml` is local and ignored and now contains real API keys directly; no `.env` file is required. `config.*.toml` variants are also ignored, while `.gitignore` explicitly re-allows only the tracked, placeholder-only `config.example.toml`.
16. Runtime configuration must not encode assumptions about a particular provider. Complete URLs, arbitrary model identifiers, and arbitrary API-key values are accepted under the OpenAI-compatible client contract.
17. `pyproject.toml` is the sole direct dependency declaration, `uv.lock` is committed, and `requirements.txt` has been removed.
18. The declared Python baseline is `>=3.12`. The project remains deliberately non-packaged until a separate source-layout/CLI refactor is justified.
19. The obsolete `src/test.py` replay experiment has been removed. Preserve `StateFromFileLoader` as a tested utility, but add any future replay feature as an explicit, versioned resume-stage interface rather than another manually configured script.
20. Chat and embedding endpoints use separate configurable minimum request intervals. The chat interval is shared across summarizer and classifier calls; the embedding interval is shared across semantic chunking and filtering. This addresses RPM quotas but deliberately does not attempt token-per-minute accounting yet.
21. Console verbosity is controlled by `-v`/`--verbose`, not TOML. Normal mode retains lifecycle messages and terminal errors but hides recoverable warnings; verbose mode adds those warnings, a safe configuration table, and stage summaries. Warnings remain recorded in `pipeline_warnings` and JSON regardless of console mode. Reporting uses standard logging plus `tqdm.write()` without a new dependency.
22. Provider endpoint changes are outside the verbose-reporting unit. The user intends to use a separately hosted OpenAI-compatible embedding endpoint while retaining the current chat provider, but will configure those ignored local values separately.
23. NVD calls use their own shared minimum-interval pacer. Because the active client does not send an NVD API key, the tracked and local default is `6.1` seconds, providing slight headroom over the keyless five-requests-per-30-seconds allowance. This pacing does not add retries or API-key support.
24. `CVE_TEST` dictionary values are authoritative benchmark annotations; nearby comments must agree with and only explain those values. Interpret the active `LABELS_DESCRIPTIONS` values rather than historical comments when auditing the fixture.

## Repository understanding

### What the current program actually is

The active entry point is still primarily a benchmark script. `src/CVE_expert_seq.py` exposes `build_pipeline()`, `run_evaluation()`, and `main()`. `main()` loads the ignored local `config.toml`, builds one LangChain `RunnableSequence`, and processes the 20 hard-coded `CVE_TEST` cases once in insertion order.

Each CVE invocation performs the entire live workflow:

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

There is no acquisition, page, chunk, embedding, or summary cache. The default run no longer repeats the same benchmark eight times, but each CVE still performs fresh live work.

### Selected live components and tracked template values

- Entry point: `src/CVE_expert_seq.py`
- Benchmark cases: 20
- Evaluation runs: 1, sequential, stable `CVE_TEST` order
- NVD request delay: `6.1` seconds in the tracked keyless example
- Chat/classifier model: user-selected placeholder
- Summarizer model: user-selected placeholder
- Embedding model: user-selected placeholder
- Chat/classifier temperature: `0.0`
- Summarizer temperature: `0.0`
- Maximum successfully extracted reference pages: 10
- Chunker: `SemanticChunkerNode`, percentile threshold amount `25.0`
- Filter: `CosineFilterNode`, query `What type of vulnerability is it?`, threshold `0.6`
- Summarizer: `CVEAwareSummarizerNode`
- Classifier: `CVEClassifierNode`
- Template output location: `logs/RUN_0.json`; both directory and run number are configurable. Historical ignored artifacts under `logs/LOG_GPT_NORANDAware/` are left untouched.

These are configuration-shape examples, not provider-specific application defaults. Model identifiers must be replaced for the selected endpoints. The live program requires a user-created ignored `config.toml` and has no fallback constants for these values.

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

Only `cve_id` is required in `CVEClassifierState`; stage outputs are optional. Stages shallow-copy the current dictionary and add their output. The state can also accumulate structured `pipeline_warnings` for recoverable reference failures.

### Failure and evaluation semantics

- `PipelineStageError` contains the stage, CVE ID, underlying exception type, and a safe message. Error serialization intentionally omits raw upstream exception messages.
- NVD request/parsing, document embedding/filtering, formatter preconditions, and classifier invocation/output validation are terminal.
- Reference scrape, chunk, and summary failures append structured `PipelineWarning` records and retain successful references.
- Classifier labels must be a non-empty list of allowed unique strings. `NONE` cannot coexist with a real label. These rules apply to active, no-RAG, confidence, and self-consistency variants.
- A successful state with warnings logs as `degraded`; without warnings it logs as `success`; a terminal exception logs as `error` with compatibility fields `error_message` and `["ERROR"]`.
- Aggregate metrics score successful and degraded states, exclude errors, and include `total`, `scored`, `successful`, `degraded`, `failed`, and `complete`.

### Resume support

The machine-specific `src/test.py` replay experiment was removed on 2026-08-30. `StateFromFileLoader` remains available and tested, but it silently omits requested fields absent from a log entry. There is no supported replay entry point. Future work should introduce named, versioned resume stages and validate artifact compatibility explicitly.

### Dependencies and environment

- `pyproject.toml` declares Python `>=3.12`, project metadata, and all packages directly imported by the active code.
- `uv.lock` pins the complete resolution; `requirements.txt` was removed by explicit user request.
- The project uses `tool.uv.package = false`: uv manages its environment, but the script-oriented source tree is not built or installed as a package.
- Former default dependencies for local Hugging Face/transformer experiments were removed because the active pipeline uses remote OpenAI-compatible clients and does not import them.
- `uv.lock` contains `langgraph` transitively because current `langchain` depends on it; active CVExpert code still does not import or use LangGraph.
- `langchain-experimental` emitted a local deprecation warning stating that it is being sunset; the selected semantic chunker currently comes from that package.
- Local observation on 2026-08-30: `uv 0.11.26`, Python `3.14.6`, the new 85-package lock resolves, the synchronized environment is consistent, and runtime imports succeed.
- `config.toml` is resolved relative to the repository root and contains both endpoint API keys directly. `.env` is not read. API-key fields are hidden from dataclass representations, but the full configuration object must still be treated as sensitive.
- The repository now has 55 offline standard-library `unittest` cases covering typed TOML parsing/validation, secret-safe representations, provider-neutral client construction and request pacing, tqdm-safe reporting, color/redaction behavior, CLI verbosity and failure handling, evaluator/runner behavior, state loading, formatting, terminal failures, classifier invariants, degraded warnings, coverage reporting, deterministic execution, and cosine normalization.

## Documentation inconsistencies

- The README now documents uv setup, provider-neutral local TOML configuration, the live entry point, pipeline, output, and offline verification. It remains intentionally concise rather than a full architecture specification.
- The current README no longer embeds `imgs/system.png`; an earlier revision did.
- `imgs/system.png` is stale: it omits explicit chunking, NVD reference ranking, embeddings, the benchmark runner, failure/degraded states, and evaluation metrics.
- Scraper documentation says references are randomly shuffled, but the current function does not shuffle them; it processes NVD-ranked order.
- Several stage docstrings call ordinary callable stages “LangGraph nodes” even though `main` uses LangChain sequencing.

## Two-branch review

### Linear `main`

`main` uses a flat taxonomy and a `RunnableSequence`. Prompts remain embedded inside summarizer/classifier classes. The active script executes the full live retrieval and classification path and catches most stage errors locally.

### `graphCVExpert`

The graph branch descends from the linear history, removes the sequential entry point, adds LangGraph entry points, changes the benchmark to hierarchical paths, externalizes prompts, and adds an iterative hierarchical classifier. Its current entry points replay a pre-existing log from a hard-coded absolute path rather than exercising the full NVD-to-classifier workflow.

Useful ideas that may be selectively ported to the linear implementation:

- prompts isolated in `src/Definitions/prompts.py`;
- batched embedding/filter requests across references;
- batched summarization requests;
- retry/backoff around NVD HTTP work;
- explicit error propagation instead of silently predicting `NONE` (ported in the first reliability batch);
- per-origin coordination for concurrent scraping;
- `zero_division=0` in metric calls (ported in the first reliability batch).

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

### Resolved P0 — Failure semantics, coverage, configuration, and cosine correctness

Implemented in the first reliability batch:

- Operational/model failures no longer become ordinary `NONE` predictions. Terminal stages raise `PipelineStageError`; reference-local failures become warnings and degraded results.
- Classifier output validation enforces allowed, non-empty, unique labels and mutual exclusion for `NONE`.
- Per-CVE logs expose success/degraded/error state, warnings, and structured error details. Aggregate output exposes coverage and cannot mark a partial run complete.
- Local TOML discovery is repository-root anchored and validation occurs before live client construction. Direct API-key fields superseded the earlier `.env`-based implementation.
- Query and document embeddings are L2-normalized. Zero document vectors score zero; zero query vectors, non-finite data, count mismatches, and dimension mismatches fail explicitly.
- Regression tests use deliberately unnormalized embeddings and model/NVD failures to pin these behaviors.

Remaining follow-up: the fixed `0.6` threshold must be recalibrated on pinned artifacts because correcting the math changes its meaning when an endpoint previously returned unnormalized vectors.

### P1 — Live acquisition still lacks caching and retry policy

The old eight-run/160-NVD-request burst is resolved: the default now makes one stable-order pass and at most one NVD request per benchmark CVE. The previous eight files were never averaged, so temperature zero plus one run matches the confirmed intent.

Remaining evidence:

- A full benchmark still performs 20 fresh NVD requests and repeats page, embedding, summary, and classification work on every invocation.
- NVD calls are paced, but there is still no NVD API-key support, bounded retry/backoff, reference-origin limiter, response cache, or persistent preprocessing artifact.
- Model endpoints now have configurable minimum request intervals, but no token-per-minute accounting, adaptive handling of quota headers, or persistent request/cost telemetry.

Impact:

- Transient failures become correctly visible but are not retried.
- Runs remain slow, externally mutable, and unnecessarily expensive to repeat.

Approach:

- Fetch and persist deterministic source/preprocessing artifacts once per CVE.
- Add API-key-aware NVD headers and bounded retry/backoff while preserving pacing for every attempt; add explicit response/content limits.
- Run any future stochastic or prompt comparison from the same pinned artifact stage.

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

### P1 — Classification remains unauditable beyond label validation

Evidence:

- Basic classifier output contains labels only, with no evidence, confidence, or provenance.
- The self-consistency experiment returns every label seen at least once across five calls; it calculates frequency but applies no acceptance threshold.

Impact:

- Predictions remain difficult to audit, and the self-consistency experiment can reduce precision.

Approach:

- Require evidence references for every selected label.
- If self-consistency is retained, define and validate a frequency threshold and failure policy.

### P1 — Benchmark coverage is too weak for optimization

Observed benchmark facts:

- 20 CVEs, including one mutually exclusive `NONE` case.
- `InputValidation` appears in 13/20 cases and `AccessControl` in 6/20.
- `XSS`, `SQLi`, and `CSRF` have zero expected examples; `SSRF`, `OutOfBoundsRead`, `UseAfterFree`, `InfoLeak`, and `ResourceExhaustion` have one each.
- Several labels have only one example.
- Many examples are famous CVEs likely known to general-purpose models, so CVE-ID memorization can mask retrieval quality.

Impact:

- Aggregate micro-F1 is dominated by common labels.
- Per-label behavior and `NONE` handling cannot be validated.
- Prompt/model changes can overfit a tiny, contaminated benchmark.

Approach:

- Preserve the documented annotation rules and re-check assignments when authoritative CVE records materially change.
- Add negative/unsupported cases and balanced coverage for every label.
- Track per-label precision/recall/F1, exact match, sample-F1, Hamming loss, coverage, latency, and cost.
- Separate development and held-out cases; include newer/less-famous CVEs and optionally mask the CVE ID in retrieval ablations.

### P2 — Reproducibility remains best-effort

Evidence:

- The active benchmark is now one insertion-order run with both chat temperatures set to zero.
- Acquisition results can change between repeated evaluations.
- Provider implementations may still vary at temperature zero, and the run does not capture artifact/config hashes or source timestamps.
- Run metadata says `RUN_N + 1` while filenames are zero-based.

Approach:

- Pin acquisition/preprocessing artifacts and record their versions/hashes.
- If repeated evaluation is reintroduced, run it from the same artifact and add an explicit cross-run stability report.

### P2 — Work is fully sequential and unbatched

Evidence:

- Scraping is sequential per CVE.
- Filtering sends one embedding request per reference.
- Summarization sends one LLM request per reference.
- CVEs are processed sequentially in one run.

Impact:

- Correct but potentially high latency and poor endpoint utilization.

Approach:

- Make concurrency explicit per external service, with independent bounded limits.
- Batch compatible embeddings/model calls.
- Add bounded parallelism only after caching, retry, and service-specific rate policies exist.

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

### Partially resolved P2 — Entry points and configuration are tightly coupled

Evidence:

- Models, temperatures, endpoint URLs, credential-variable names, NVD URL/timeout, reference limit, semantic threshold, cosine query/threshold, run number, and log directory now come from typed, validated TOML settings.
- `build_pipeline(runtime_config)` is reusable and `main()` is testable, but benchmark execution, scoring, persistence, and live construction still share one module.
- The duplicate replay runner has been removed; no supported resume entry point currently exists.

Approach:

- Typed configuration is complete; introduce separate pipeline/runner factories and commands when splitting the reusable classifier from the benchmark.
- Provide separate classify and benchmark commands.
- Keep resume-stage selection an input rather than a separate copied script.

### Partially resolved P2 — Structure and dependency hygiene impede safe change

Evidence:

- Linear stages live under `Graph/Nodes` and retain graph-specific names/docstrings.
- Prompts are embedded in large classes, making versioning and prompt-only tests difficult.
- The entry points use wildcard evaluator imports.
- Broad exceptions obscure expected failure modes.
- The 37-case offline unit regression suite covers the reliability and configuration migrations, but there are no controlled integration, artifact-contract, prompt snapshot, or CI checks.
- Dependencies are now declared and reproducibly locked. The remaining structural issues are module layout, prompt isolation, experiment cleanup, and CI/integration coverage.

Approach:

- Add tests before moving modules.
- Externalize/version prompts and schemas.
- Gradually introduce a neutral pipeline namespace with compatibility imports if a move is justified.
- Keep `pyproject.toml` and `uv.lock` synchronized in dedicated dependency changes.

## Recommended improvement sequence

Do not start all of these at once. Keep each unit reviewable and measure behavior after each quality-affecting change.

1. **Completed reliability foundation**
   - Added an offline unit suite that currently has 55 tests covering evaluator/runner, TOML configuration, provider-neutral client construction and pacing, NVD failures, formatter, filters, classifier variants, warnings, coverage, and state loading.
   - Defined terminal error and degraded-warning semantics, fail-fast mode-aware configuration, classifier invariants, deterministic single-run behavior, coverage reporting, and correct cosine normalization.
   - Still needed from the original contract work: a versioned artifact manifest and controlled integration fixtures.
2. **Reliable acquisition and artifacts — recommended next**
   - NVD minimum-interval pacing is complete. Add NVD key support, bounded retry/backoff, English-description selection, richer structured fields, caching, and provenance.
   - Add safe bounded scraping with content-type/size validation.
   - Define versioned resume artifacts before optimizing prompts/retrieval against mutable live inputs.
3. **Reusable pipeline and benchmark split**
   - Extract model/stage factories and a reusable single/batch classify API.
   - Build a separate benchmark runner on top.
   - Add named resume-stage behavior only after a versioned artifact contract exists; the obsolete replay script has been removed.
4. **Retrieval and evidence quality experiments**
   - Evaluate chunkers, target-specific retrieval, top-k/token limits, batching, and structured evidence extraction one variable at a time.
   - Add prompt-injection tests and preserve source citations.
   - Recalibrate the existing `0.6` cosine threshold on pinned inputs before interpreting comparison results.
5. **Benchmark audit and reporting**
   - Resolve annotation contradictions with explicit rules.
   - Expand label/negative coverage and add held-out evaluation.
   - Add per-label, exact-match, stability, latency, and cost reporting.
6. **Only then consider larger structural cleanup**
   - Neutral module names, packaging, prompt modules, CI, and optional taxonomy interfaces. Dependency locking is complete.
   - Do not adopt LangGraph merely to reuse graph-branch improvements.

## Candidate first change units

These are proposals, not authorization to edit production code:

1. NVD client hardening: English description selection, API-key support, explicit retryable statuses, and bounded exponential backoff integrated with the existing shared pacer.
2. Versioned stage-artifact schema plus a parameterized loader for named resume stages.
3. Bounded scraper policy for URL scheme, response/content type, downloaded size, and per-origin coordination.
4. Cached retrieval-quality harness to recalibrate cosine threshold and compare chunk/query/top-k choices without live-source drift.
5. Benchmark annotation audit and negative/per-label coverage plan before changing `CVE_TEST`.

## Open questions for future work

- What public interface should the reusable classifier expose first: Python API, CLI, or both?
- Is an NVD API key available for development/production? If added, replace the keyless `6.1`-second default with an explicitly reviewed keyed rate policy.
- What token accounting, adaptive quota handling, and cost telemetry should supplement the configured model-request intervals?
- Which stages and fields must version 1 of the replay artifact support?
- Should cached source pages be stored in repository-external artifacts, logs, or a dedicated cache directory?
- Who will approve benchmark annotation changes, especially ambiguous mechanism-versus-impact cases?
- What minimum evidence format is required for a label to be accepted: source ID, quote/span, URL, confidence, or all of these?

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

### 2026-08-29 — First reliability and correctness batch

- `390d6c8` added the offline standard-library regression harness.
- `db3ee28` added repository-root `.env` loading and live/replay configuration validation.
- `fea9fb0` added `PipelineStageError`, stage-dependent optional state, terminal failure propagation, and classifier output validation across all variants.
- `4ec8df2` added structured reference warnings, degraded results, structured terminal errors, metric coverage fields, and `zero_division=0`.
- `50b752a` removed the eight outer executions, shuffle, and executor from the active runner; added `build_pipeline()`/`main()`; and set summarizer/classifier temperatures to `0.0`.
- `9a3a704` implemented L2-normalized cosine similarity with zero-vector, non-finite, count, and dimension handling.
- Final offline suite at the code snapshot: 33 tests passing. Python compilation and `uv pip check` passed.
- Taxonomy, benchmark fixture, prompts, threshold `0.6`, semantic threshold `25`, retrieval query, dependencies, and runtime artifact path/schema were deliberately left unchanged.
- No NVD request, page scrape, embedding request, chat/LLM request, Hugging Face Hub operation, or credential disclosure occurred during implementation or verification.

### 2026-08-30 — Provider-neutral TOML and uv migration

- `c41ddde` replaced endpoint/model constants with typed, strict `config.toml` loading; added the tracked provider-neutral `config.example.toml`; ignored local `config.toml`; and kept secrets exclusively in environment variables named by TOML.
- Complete chat and embedding base URLs are now passed through unchanged. NVD URL/timeout, maximum reference pages, semantic threshold, cosine query/threshold, and evaluation location/run number are also injected from the same validated settings object.
- The linear pipeline sequence and classification behavior did not change. The live entry point now loads configuration once and passes it to pipeline construction and evaluation metadata.
- `d175957` added `pyproject.toml`, declared Python `>=3.12` and direct imports, created `uv.lock`, removed unused local-transformer dependencies from the default environment, and removed `requirements.txt` by user request.
- Removed the obsolete `src/test.py` replay experiment and its machine-specific path while retaining the tested `StateFromFileLoader` utility for future versioned resume work.
- Expanded and updated README/agent guidance for `uv sync`, local TOML creation, arbitrary OpenAI-compatible endpoints, credential-variable indirection, and safe offline verification.
- Synchronized the lock into `.venv`; all 38 offline tests, compilation, `uv lock --check`, `uv pip check`, and whitespace checks passed. No NVD, web scraping, embedding, or chat/model request was made.

### 2026-08-30 — Direct TOML credentials

- Superseded the environment-variable indirection from `c41ddde` at the user's request: `[chat].api_key` and `[embedding].api_key` are now read directly from ignored `config.toml`; `.env` is no longer loaded or required.
- Marked secret dataclass fields with `repr=False`, added empty-key and representation regression tests, and kept `config.example.toml` limited to obvious placeholders.
- Expanded `.gitignore` to cover `config.toml` and `config.*.toml` while explicitly re-allowing `config.example.toml`.
- Removed the direct `python-dotenv` dependency; it may remain in `uv.lock` transitively through third-party packages.

### 2026-08-30 — Model request pacing and embedding compatibility

- `d023bae` added separate `[chat].request_delay_seconds` and `[embedding].request_delay_seconds` settings. A thread-safe minimum-interval hook paces every synchronous HTTP attempt, including SDK retries; summarizer/classifier calls share one chat pacer and semantic-chunker/filter calls share one embedding pacer.
- Added `[embedding].check_embedding_ctx_length` so raw-text versus OpenAI token-array behavior is provider-neutral and explicitly configurable rather than hard-coded for one service.
- The ignored local configuration uses modest headroom over the currently reported RPM limits. The tracked example remains provider-neutral, uses `0.0`, and documents the `60 / RPM` calculation. Token-per-minute enforcement remains deferred until measurements show it is necessary.
- Declared the directly imported `openai` client in `pyproject.toml` and updated `uv.lock` without changing the resolved package set.
- Added five regression tests, bringing the offline suite to 42 passing tests. Compilation, lock consistency, installed dependency consistency, and whitespace checks also passed. No NVD, reference, embedding, or chat request was made during verification.

### 2026-08-30 — Verbose pipeline reporting (`d435211`)

- Added a centralized project logger whose handler writes through `tqdm.write()`, colors interactive warnings yellow and errors red, honors `NO_COLOR`, redacts configured secrets, sanitizes displayed URLs, and reduces technical exceptions to concise single-line diagnostics.
- Added `-v`/`--verbose`, a safe effective-configuration table emitted before live client construction, and aggregate operation summaries across the active NVD, scrape, chunk, filter, summarize, format, classify, and evaluation stages.
- Normal mode retains lifecycle output and terminal errors while hiding recoverable warnings. Verbose mode emits those warnings immediately; they remain in `pipeline_warnings` and JSON in both modes. JSON failure fields and pipeline failure semantics are unchanged.
- Added offline regression coverage for output-level filtering, tqdm-safe writes, ANSI colors, `NO_COLOR`, redaction, URL sanitization, concise upstream errors (including long provider tokens), safe configuration rendering, immediate warning reporting, CLI verbosity, and traceback-free top-level failures. The suite currently has 54 passing tests.
- Live verification first exposed that the checked-out `CVE_TEST` currently contains all 20 fixtures; the exact CLI run was interrupted during the second CVE to avoid unintentionally completing the full benchmark. A second invocation restricted `CVE_TEST` to its first item in memory, leaving the source untouched, and completed the one-CVE reporting check.
- The one-CVE run verified the safe table, stage summaries, tqdm-safe yellow warnings, a red terminal error, and a final `successful=0 degraded=0 failed=1` summary without a traceback. The unchanged local embedding configuration still produced recoverable semantic-chunker HTTP 400 batch-limit errors and HTTP 429 quota errors, followed by a terminal HTTP 429 filter failure. The ignored old-path `RUN_0.json` was rewritten as authorized.
- No configuration values or log paths were changed in this reporting unit. Its complete diff, offline verification, and authorized one-CVE live output were shown before commit.

### 2026-08-30 — Simplified evaluation log path (`9f16957` snapshot)

- Changed the tracked template and ignored local configuration from `logs/LOG_GPT_NORANDAware` to `logs`, so run 0 resolves to `logs/RUN_0.json`.
- Updated user and agent documentation to match. Existing ignored files under `logs/LOG_GPT_NORANDAware/` are intentionally untouched and remain recoverable.

### 2026-08-30 — NVD request pacing

- Added validated `[nvd].request_delay_seconds` configuration and one shared `MinimumIntervalPacer` instance across all CVE lookups in a benchmark run.
- The pacer runs immediately before every NVD HTTP attempt. The first request remains immediate; later request starts are separated by the configured minimum interval even when the previous request failed.
- The tracked and ignored local configurations use `6.1` seconds for the current keyless NVD client. API-key headers, retry/backoff, and caching remain separate future work.
- All 55 offline tests, compilation, lock consistency, installed dependency consistency, whitespace checks, local configuration validation, and a secret-oriented scan passed. No NVD, reference, embedding, or chat request was made during verification.

### 2026-08-30 — `CVE_TEST` label audit

- Researched all 20 fixtures against the current NVD records plus vendor advisories and primary technical analyses. Treated the `CVE_TEST` values as ground truth and rewrote every evidence comment so it agrees with the value.
- Applied the flat-taxonomy rule that every directly supported matching label is included, while consequences and exploit preconditions do not manufacture mechanisms: RCE alone is not CodeInjection, unauthenticated reach alone is not AccessControl, and companion CVEs are classified separately.
- Changed 13 fixtures. Notable corrections include `CVE-2025-59145` to `NONE`, Log4Shell gaining the Apache CNA's CWE-400/ResourceExhaustion classification, Heartbleed losing the logical InfoLeak label, FortiWeb losing CommandInjection, ProxyShell losing UntrustedDeserialization, ProxyLogon retaining only UntrustedDeserialization, and IngressNightmare retaining only AccessControl.
- The resulting fixture has 40 assignments across 20 cases: 13 InputValidation, 6 AccessControl, 4 each CodeInjection and UntrustedDeserialization, 3 PathTraversal, 2 each CommandInjection and BufferOverflow, one each SSRF, OutOfBoundsRead, UseAfterFree, InfoLeak, ResourceExhaustion, and NONE, and zero XSS, SQLi, or CSRF examples.
- Added fixture-invariant tests for nonempty, unique, allowed labels and mutually exclusive `NONE`. All 57 offline tests, Python compilation, lock consistency, installed dependency consistency, and whitespace checks passed.

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
