# AGENT_NOTES.md

Persistent working memory for CVExpert. Read this file with `AGENTS.md` before starting work. Update it when project understanding, decisions, findings, scope, progress, or open questions change. Never store credential values.

## Current status

- Last updated: 2026-09-20 (Europe/Rome)
- Active branch: `main`
- Linear code snapshot includes the direct-TOML credential migration documented in the 2026-08-30 work log below.
- Graph branch snapshot reviewed for comparison: `graphCVExpert` at `411baf6`
- Documentation commit completed: `c95e0f0` (`docs: add repository guidance for coding agents`)
- Initial review/memory commit completed: `bf12e38` (`docs: add persistent agent notes and pipeline review`)
- First reliability batch implemented through `9a3a704` (`fix: compute true cosine similarity`)
- Model request pacing implemented in `d023bae` (`feat: pace model endpoint requests`).
- Current phase: three JSON taxonomy/benchmark pairs replace the hard-coded Python labels and 20-case fixture. CLI CVE IDs are required; optional `--benchmark` scores only requested cases.
- The linear stage order remains unchanged. Classification now groups labels under an approximate input budget and enforces `most_specific` ancestor removal.
- The filter now fetches its shared query embedding during CVE processing so an upstream failure is attributed to one CVE; console errors retain stage context even for HTML gateway responses.
- Live `RunnableSequence` runs now persist per-CVE stage timings without storing prompt or response content.
- Semantic chunking now narrows only very large multi-CVE indexes around the requested identifier while retaining the full extracted page and logging character counts.
- `IMPLEMENTATION_REPORT.md` records the complete fixture/CLI migration, live investigation, measured performance change, limitations, and recommended follow-up work.
- Benchmark mode prints a final table comparing expected and predicted labels with per-CVE and aggregate metrics plus coverage; classification-only mode does not print scores.
- The reliability hardening tranche is complete. Static verification and the authorized hierarchical one-CVE and ten-CVE live validations passed; no code-caused live defect remains open.

## Durable user decisions

1. Work exclusively on the first, linear implementation on `main` after the initial two-branch review.
2. Treat code as authoritative and cross-check all documentation against it.
3. Maintain this file as a persistent second memory for understanding, decisions, findings, work state, and open questions.
4. Prefer logically cohesive commits. Commits may be larger when a change naturally spans tests and integration, while unrelated configuration, dependency, documentation, benchmark, and architectural work should remain separated. Explain and discuss bug fixes or larger behavior changes before implementation.
5. The desired long-term product shape is both:
   - a reusable classifier that can process arbitrary individual/batch CVEs; and
   - a separate, repeatable benchmark/evaluation harness.
6. The active linear pipeline selects a taxonomy JSON through TOML and supports the provided flat, hierarchical, and hybrid fixtures. It does not use LangGraph.
7. Preserve each taxonomy's `most_specific` policy: return directly supported mechanisms and omit an ancestor when a selected descendant is present. The classifier groups labels into bounded calls while retaining the linear stage sequence.
8. `NONE` is mutually exclusive and valid only after successful classification across every group. Do not infer mechanism labels from impacts, preconditions, or companion CVEs.
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
24. The three 50-case expected-classification JSON files are the configured benchmark annotations. Their rationales and source lists are provenance, not runtime instructions; validate their canonical taxonomy fingerprints before evaluation.
25. `[fixtures].taxonomy_file` is required; `[fixtures].expected_classification_file` is optional and loaded only with `--benchmark`. Positional CVE IDs are always required. With `--benchmark`, each requested ID must have an expected case; unrequested cases are ignored and the requested subset is scored in CLI order.
26. `[classification].max_input_tokens` is an approximate rendered prompt and schema budget, estimated as `ceil(1.2 × UTF-8 bytes ÷ 3)`. The tracked example uses 12,000; provider tokenization may differ.
27. `--benchmark` should finish with a console table that makes each requested CVE's expected and predicted labels, per-CVE scores, aggregate scores, and coverage directly visible. Terminal failures stay in the table with unavailable metrics rather than being omitted.
28. The 2026-09-20 reliability tranche keeps pipeline order and classification semantics unchanged. Cost accounting, cache/resume, source-excerpt provenance, hierarchy-aware routing, batching/concurrency, large-body log deduplication, and dormant-code cleanup are explicitly deferred.
29. Reliability budgets use tokens rather than monetary cost. Existing ignored `config.toml` files must remain valid through active defaults, and live validation must preserve the existing `logs/RUN_0.json` while reporting the actually selected hierarchical taxonomy.

## Repository understanding

### What the current program actually is

`src/CVE_expert_seq.py` exposes `build_pipeline()`, `run_evaluation()`, `run_classification()`, and `main()`. It loads ignored local `config.toml` and the selected taxonomy before client construction, builds one LangChain `RunnableSequence`, then processes explicit CVE IDs in CLI order. Optional benchmark scoring uses only their expected cases.

Each CVE invocation performs the entire live workflow:

```text
cve_id
  -> NVD description + ranked reference URLs
  -> fetched/extracted reference pages
  -> semantic chunks
  -> embedding-thresholded chunks
  -> LLM summaries per reference
  -> combined RAG context
  -> structured LLM classification over token-bounded label groups
  -> per-CVE results and benchmark-only exact-match accuracy and aggregate micro metrics
  -> JSON run log
```

There is no acquisition, page, chunk, embedding, or summary cache. Each requested CVE still performs fresh live work. A benchmark run processes each selected JSON case once.

### Selected live components and tracked template values

- Entry point: `src/CVE_expert_seq.py`
- Supplied benchmark cases: 50 in each of the flat, hierarchical, and hybrid pairs
- Evaluation runs: 1, sequential, CLI CVE order; runs without `--benchmark` have no ground-truth scoring
- Supplied taxonomy labels: 9 flat, 39 hierarchical, 84 hybrid
- Classifier input estimate: 12,000 tokens per call in the tracked template
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
- Benchmark output pattern: `logs/RUN_<number>_<UTC timestamp>_<UUID prefix>.json`; classification-only outputs use analogous unique `CLASSIFY_*.json` names. Historical `logs/RUN_0.json` and ignored artifacts under `logs/LOG_GPT_NORANDAware/` are left untouched.

These are configuration-shape examples, not provider-specific application defaults. Model identifiers must be replaced for the selected endpoints. The live program requires a user-created ignored `config.toml` and has no fallback constants for these values.

### Stage state

`CVEClassifierState` documents a single dictionary that accumulates:

- `cve_id`
- `nvd_description`
- `nvd_url_references`
- `nvd_references_pages`
- `nvd_references_chunks`
- optional `reference_focus` character counts when a broad multi-CVE index was narrowed for chunking
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
- The offline standard-library `unittest` suite covers typed TOML and JSON validation, provider-neutral client construction and pacing, reporting, CLI modes, grouped classification, evaluator/runner behavior, state loading, formatting, failure semantics, and cosine normalization.

## Documentation inconsistencies

- The README now documents uv setup, provider-neutral local TOML configuration, the live entry point, pipeline, output, and offline verification. It remains intentionally concise rather than a full architecture specification.
- The current README no longer embeds `imgs/system.png`; an earlier revision did.
- `imgs/system.png` is stale: it omits explicit chunking, NVD reference ranking, embeddings, the benchmark runner, failure/degraded states, and evaluation metrics.
- Scraper documentation says references are randomly shuffled, but the current function does not shuffle them; it processes NVD-ranked order.
- Several stage docstrings call ordinary callable stages “LangGraph nodes” even though `main` uses LangChain sequencing.

## Two-branch review

### Linear `main`

`main` uses the selected JSON taxonomy and a `RunnableSequence`. Prompts remain embedded inside summarizer/classifier classes. The active script executes the full live retrieval and classification path and catches most stage errors locally. Hierarchical labels are handled inside the classifier stage, without graph orchestration.

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

- A run still performs one fresh NVD request per requested CVE and repeats page, embedding, summary, and classification work on every invocation.
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

### P1 — Supplied benchmark coverage remains incomplete for optimization

Observed benchmark facts:

- Each supplied benchmark has 50 cases and no `NONE` case; seven cases have multiple labels.
- The flat set covers eight of nine labels, the hierarchical set 18 of 39, and the hybrid set 22 of 84.
- The availability-and-resources family is unrepresented; many specific labels remain untested.
- Live CVE evidence can change, and CVE-ID memorization can still mask retrieval quality.

Impact:

- Aggregate micro-F1 can hide poor performance on rare labels.
- `NONE` handling cannot be validated by the supplied expected cases.
- Prompt/model changes can overfit a small, mutable live benchmark.

Approach:

- Preserve fixture rationales and source provenance; re-check assignments when authoritative CVE records materially change.
- Add negative/unsupported cases and balanced coverage for every label.
- Track per-label precision/recall/F1, exact match, sample-F1, Hamming loss, coverage, latency, and cost.
- Separate development and held-out cases; include newer/less-famous CVEs and optionally mask the CVE ID in retrieval ablations.

### P2 — Reproducibility remains best-effort

Evidence:

- A benchmark run processes the requested JSON cases once in CLI order with both tracked chat temperatures set to zero.
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
- The state/log retains full pages, chunks, filtered chunks, summaries, and RAG. Taxonomy path and fingerprint are recorded, but there is still no versioned stage-artifact contract or config hash.

Approach:

- Define a versioned artifact schema with pipeline/config hashes and timestamps.
- Use atomic writes or append-only per-CVE records plus a final manifest.
- Separate reusable stage artifacts from concise evaluation results.

### Partially resolved P2 — Entry points and configuration are tightly coupled

Evidence:

- Models, temperatures, endpoint URLs, credential-variable names, NVD URL/timeout, reference limit, semantic threshold, cosine query/threshold, run number, and log directory now come from typed, validated TOML settings.
- `build_pipeline(runtime_config, taxonomy)` is reusable and the CLI has explicit classification and benchmark modes, but scoring, persistence, and live construction still share one module.
- The duplicate replay runner has been removed; no supported resume entry point currently exists.

Approach:

- Typed configuration and CLI mode selection are in place; introduce separate pipeline/runner modules if a Python library API or independent commands are needed.
- Keep resume-stage selection an input rather than a separate copied script.

### Partially resolved P2 — Structure and dependency hygiene impede safe change

Evidence:

- Linear stages live under `Graph/Nodes` and retain graph-specific names/docstrings.
- Prompts are embedded in large classes, making versioning and prompt-only tests difficult.
- The entry point now uses explicit evaluator imports.
- Broad exceptions obscure expected failure modes.
- The offline unit suite covers reliability, configuration, JSON fixtures, and classifier grouping, but there are no controlled integration, artifact-contract, prompt snapshot, or CI checks.
- Dependencies are now declared and reproducibly locked. The remaining structural issues are module layout, prompt isolation, experiment cleanup, and CI/integration coverage.

Approach:

- Add tests before moving modules.
- Externalize/version prompts and schemas.
- Gradually introduce a neutral pipeline namespace with compatibility imports if a move is justified.
- Keep `pyproject.toml` and `uv.lock` synchronized in dedicated dependency changes.

## Recommended improvement sequence

Do not start all of these at once. Keep each unit reviewable and measure behavior after each quality-affecting change.

1. **Completed reliability foundation**
   - Added an offline unit suite covering evaluator/runner, TOML and JSON configuration, provider-neutral client construction and pacing, NVD failures, formatter, filters, classifier variants, warnings, coverage, and state loading.
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
   - Neutral module names, packaging, prompt modules, CI, and reusable taxonomy APIs. Dependency locking is complete.
   - Do not adopt LangGraph merely to reuse graph-branch improvements.

## Candidate first change units

These are proposals, not authorization to edit production code:

1. NVD client hardening: English description selection, API-key support, explicit retryable statuses, and bounded exponential backoff integrated with the existing shared pacer.
2. Versioned stage-artifact schema plus a parameterized loader for named resume stages.
3. Bounded scraper policy for URL scheme, response/content type, downloaded size, and per-origin coordination.
4. Cached retrieval-quality harness to recalibrate cosine threshold and compare chunk/query/top-k choices without live-source drift.
5. Benchmark annotation audit and negative/per-label coverage plan before changing the selected JSON expectations.

## Open questions for future work

- What public interface should the reusable classifier expose first: Python API, CLI, or both?
- Is an NVD API key available for development/production? If added, replace the keyless `6.1`-second default with an explicitly reviewed keyed rate policy.
- What token accounting, adaptive quota handling, and cost telemetry should supplement the configured model-request intervals?
- Which stages and fields must version 1 of the replay artifact support?
- Should cached source pages be stored in repository-external artifacts, logs, or a dedicated cache directory?
- Who will approve benchmark annotation changes, especially ambiguous mechanism-versus-impact cases?
- What minimum evidence format is required for a label to be accepted: source ID, quote/span, URL, confidence, or all of these?

## Work log

### 2026-09-20 — Reliability foundation

- Added optional validated defaults for service timeouts, retry attempts, content/chunk/model limits, and CVE/run request-token-time budgets without requiring changes to ignored local configuration.
- Added shared execution-context, budget, retry, `Retry-After`, jitter, and audit primitives. SDK retry disabling and stage integration follow in the subsequent reliability units.
- Minimum-interval pacing now reports its wait duration for request telemetry.
- Declared the already-transitive `httpx` package as a direct dependency because production code will construct component-level model timeouts.
- The complete offline suite passes with 94 tests; compilation, lock validation, installed dependency checks, and whitespace checks pass.

### 2026-09-20 — NVD acquisition hardening

- NVD requests now support a shared session, optional API-key header, explicit connect/read timeouts, repository-owned retries, pacing telemetry, and safe partial state on terminal failure.
- Response parsing verifies the requested CVE ID, requires an English description, skips malformed references with warnings, normalizes public HTTP(S) reference syntax, and removes exact normalized duplicates while retaining ranked order.
- Added reusable URL normalization for the reference trust boundary. Public-address resolution is applied by the scraper unit rather than during NVD parsing.
- The complete offline suite passes with 96 tests; compilation, lock validation, installed dependency checks, and whitespace checks pass.

### 2026-09-20 — Reference trust boundary and limits

- Replaced Trafilatura's implicit downloader with a shared streaming `requests.Session`; Trafilatura now receives only already-bounded bytes for extraction.
- Reference fetching revalidates every redirect, rejects credentials and non-public address resolution, permits an explicit textual content-type set, applies connect/read timeouts and repository retries, and enforces declared plus streamed byte limits.
- Per-reference and per-CVE extracted-character limits produce explicit degraded warnings and deterministic truncation. Ranked sequential processing and the successful-page limit remain unchanged.
- The complete offline suite passes with 102 tests; compilation, lock validation, installed dependency checks, and whitespace checks pass.

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

### 2026-09-18 — Configured JSON taxonomies and optional benchmark mode

- Replaced the hard-coded Python taxonomy and 20-case dataset with byte-for-byte copies of three supplied JSON pairs under `fixtures/flat`, `fixtures/hierarchical`, and `fixtures/hybrid`. They contain 9, 39, and 84 labels respectively, and 50 cases each.
- Added typed fixture loading with parent/cycle checks, `most_specific` validation, reserved `NONE` handling, case/provenance validation, and canonical JSON SHA-256 pair verification. The attached Markdown readmes were treated as contextual data, not implementation instructions.
- Added required taxonomy and optional expected-classification paths in TOML; the ignored local configuration was extended without changing existing credential values. The tracked example selects the flat pair.
- Split CLI use into positional CVE classification with no scores and explicit `--benchmark` evaluation. Both modes share the linear pipeline; benchmark logs keep `RUN_N.json`, while classification logs receive unique names.
- The summarizer now receives root-label guidance. The classifier estimates rendered prompt plus schema size under `[classification].max_input_tokens`, groups labels deterministically, and removes selected ancestors across groups. A group failure is terminal; `NONE` requires all groups to select no label.
- At this snapshot, all 76 offline tests pass; compilation, lock consistency, installed dependency consistency, whitespace, selected local configuration, and byte-for-byte fixture checks pass. No live NVD, reference, embedding, or chat calls were made.

### 2026-09-18 — CLI-selected benchmark subsets

- Required positional CVE IDs for all runs; `--benchmark` is optional. In benchmark mode, requested IDs are matched against the configured JSON before client construction and scored in CLI order. Missing requested IDs fail setup; extra JSON cases are harmless.
- Added per-CVE and aggregate exact-match accuracy alongside micro precision, recall, and F1. Aggregate metrics and coverage describe only the requested subset; terminal failures remain excluded from scores.
- Updated CLI, fixture, runner, and evaluator tests plus README and repository guidance. All 81 offline tests, compilation, lock consistency, installed dependency consistency, and whitespace checks passed. No live service calls were made.

### 2026-09-18 — Live debugger investigation of a reported HTTP 502

- Ran one CVE and then the first ten flat-fixture CVEs under `debugpy` with the configured endpoints. The ten-case benchmark wrote to a temporary directory to preserve the existing `logs/RUN_0.json`; it completed with 6 success, 4 degraded, and 0 terminal errors. All 17 warnings were reference scrape `ValueError`s, not HTTP 502s. Scored subset accuracy, micro precision, recall, and F1 were each 0.9.
- `CVE-2020-14864` was the sole label mismatch: the expected `PathAndResourceSelection` became `AccessControl`. Its two filtered reference entries yielded no summaries, leaving a generic NVD description about unauthorized access in the classifier context. This is evidence of thin technical context, not proof of a taxonomy or prompt defect.
- The reported HTML HTTP 502 did not recur. The installed OpenAI client retries HTTP 5xx responses twice by default; the source endpoint cannot be identified from the pasted truncated console line. The filter previously fetched its query embedding during pipeline construction, so a 502 there could abort the whole batch before any per-CVE log existed.
- Moved that shared query embedding request into the filter stage and cache it after success. A failure now produces a per-CVE terminal filter record and the next CVE can try again. Console errors put safe stage/CVE context first and replace HTML gateway bodies with a short diagnostic. An offline fake covers a transient query-embedding failure; one post-fix live CVE run under `debugpy` completed successfully. All 83 offline tests, compilation, lock consistency, installed dependency consistency, and whitespace checks passed.

### 2026-09-18 — Ten-CVE timing rerun

- Reran the first ten flat-fixture CVEs under `debugpy` with a temporary profiling wrapper and isolated output; the existing `logs/RUN_0.json` was preserved. The run took about 265 seconds and again ended with 6 success, 4 degraded, 0 terminal errors, and 0.9 exact-match accuracy/micro precision/recall/F1.
- Measured stage totals: semantic chunking 81.8 seconds, summarization 67.7, classification 46.0, reference extraction 38.1, cosine filtering 20.3, NVD 10.6, and pipeline construction 0.2. `CVE-2020-14864` (62.2 seconds) and `CVE-2016-9079` (80.4 seconds) account for about 54% of pipeline time. The former extracted a 126,192-character multi-CVE Oracle advisory and produced no accepted summary; the latter had eight pages and 194 chunks. A short final CVE still took 18.1 seconds in classification, showing endpoint latency varies independently of evidence length.
- Added a LangChain callback to record top-level stage wall times in each live run's CVE log, including the failed stage. It records only stage name, duration, and success/error status. These measurements include client pacing and remote service latency, so they do not isolate provider compute time.
- The timing change passed all 84 offline tests, compilation, lock consistency, installed dependency consistency, and whitespace checks.

### 2026-09-19 — Broad multi-CVE reference focusing

- The timing profile identified a 126,192-character Oracle advisory index with 403 distinct CVE IDs as avoidable semantic-chunking work for `CVE-2020-14864`. The requested identifier appeared twice, and the page produced 159 chunks while contributing no accepted summary.
- Before semantic chunking, pages of at least 50,000 characters with at least 100 distinct CVE IDs are now reduced to merged excerpts spanning 2,000 characters on either side of each requested-CVE occurrence. The rule does not alter smaller pages, target-specific long analyses, or indexes that omit the requested CVE. Full extracted text remains in state and logs; `reference_focus` records original/focused character counts.
- An isolated live rerun of `CVE-2020-14864` reduced elapsed time from about 62.2 to 8.3 seconds and semantic chunks from 159 to 3 while preserving its prior `AccessControl` prediction.
- A full live rerun of the first ten flat cases under `debugpy` took about 204.6 seconds versus 264.5 seconds in the preceding profile, a 22.6% reduction. It again completed with 6 success, 4 degraded, 0 terminal errors, unchanged predictions, and 0.9 exact-match accuracy/micro precision/recall/F1. Service timing and scraped-page availability vary, so this is an end-to-end observation rather than a controlled microbenchmark.
- `CVE-2016-9079` remains the dominant case at about 87.2 seconds because its eight target-specific sources generated 194 chunks; the broad-index rule intentionally does not change those pages. Persistent caching, embedding reuse, and bounded reference work remain higher-value follow-up options.
- The change passed all 87 offline tests, compilation, lock consistency, installed dependency consistency, and whitespace checks.
- Added `IMPLEMENTATION_REPORT.md` as the detailed user-requested record of the full JSON migration and debugger investigation. It contains no credentials or endpoint values and notes that `.vscode/launch.json` remains ignored and uncommitted.

### 2026-09-19 — Benchmark score table

- Benchmark completion now prints one progress-safe aligned table in normal and verbose modes. Rows preserve requested CVE order and show status, expected labels, predicted labels, exact-match accuracy, micro precision, micro recall, and micro F1.
- The final row shows aggregate metrics. A coverage line shows successful, degraded, failed, scored/total, and completeness values. Terminal failures remain visible with `—` score cells; classification-only runs do not print the table.
- All 88 offline tests, compilation, lock consistency, installed dependency consistency, and whitespace checks passed. No live service calls were needed for this output-only change.

### 2026-09-20 — Reliability hardening through filtering

- Added backward-compatible resilience defaults, a shared three-attempt full-jitter retry executor, monotonic CVE/run request-token-time ledgers, and per-attempt audit aggregation. `httpx` is now a direct dependency; SDK retries will be disabled when the model clients are wired into these controls.
- Hardened NVD lookup with a shared session, explicit connect/read timeouts, optional API-key support, repository retries, exact returned-ID validation, explicit English-description selection, independently validated references, URL normalization, ordered deduplication, and partial warning preservation.
- Replaced implicit page downloading with bounded streaming fetches. Initial and redirected URLs are limited to credential-free HTTP(S) destinations that resolve only to global addresses, redirects are manually capped and revalidated, content types are allowlisted, declared/streamed byte limits are enforced, and extracted text is bounded per reference and CVE.
- Added deterministic per-reference and per-CVE semantic chunk caps. Filtering keeps query embedding failure terminal, isolates document embedding/cosine failures by reference, preserves successful references and warnings, and becomes terminal only when every non-empty reference fails.
- The four commits through this point pass 104 offline tests plus compilation, lock consistency, installed dependency consistency, and whitespace checks. No live service call has been made during this tranche yet.

### 2026-09-20 — Bounded model requests and structured repair

- Disabled OpenAI SDK retries for active chat and embedding clients and configured explicit connect/read/write/pool timeouts. Synchronous embedding and structured chat calls now use repository-owned three-attempt retry policies and share the existing stage-specific pacers.
- Added conservative per-call input estimates and configured output-token reservations. Oversized summarizer evidence is deterministically truncated with a degraded warning; classifier group preflight and `most_specific` behavior remain unchanged.
- Active summarizer and classifier calls retain raw structured-response metadata for auditing, validate parsed results, and make at most one bounded repair request containing the validation problem and prior output as delimited untrusted data. Exhausted summarizer repair degrades one reference; exhausted classifier repair remains terminal.
- Scraped and classified evidence prompts now explicitly identify external content as untrusted and prohibit embedded instructions. Stable prompt/schema version constants were introduced for the forthcoming run metadata.
- Provider token usage, request IDs, and whitelisted rate-limit headers are captured when exposed, with estimates retained otherwise; telemetry never stores prompts, responses, credentials, or raw exception text. All 109 offline tests and the complete static verification gate pass.

### 2026-09-20 — Enforced execution budgets and request audit

- Bound one shared monotonic run ledger and one monotonic CVE ledger around actual pipeline execution. Every repository-controlled NVD, redirect, reference, embedding, summary, repair, and classifier attempt reserves request capacity; model attempts also reserve conservative input plus maximum-output tokens and reconcile to provider usage when available.
- CVE/run request, token, and wall-clock exhaustion is terminal. Run exhaustion prevents all untouched remaining CVEs from invoking the pipeline, while each receives an explicit budget error entry. Budget exhaustion is no longer accidentally degraded by reference or semantic-chunk recovery paths.
- Each CVE artifact entry now includes content-free per-attempt audit records, aggregates by stage, and a CVE budget snapshot. Run-level aggregates include requests, retries, repairs, token source/usage, pacing, retry delay, latency, and shared budget use.
- Terminal entries preserve accumulated warnings and small content-free partial-stage counts. Inactive motivation/confidence values now consistently serialize as `{}`, and monotonic per-CVE timing is named `duration_seconds`.
- Added offline coverage for run short-circuiting, CVE token preflight, pacing versus retry delay, deadline-aware retry cancellation, provider versus estimated token usage, repair counts, safe headers/request IDs, and absence of prompt/response/secret material. All 113 offline tests and the full static gate pass.

### 2026-09-20 — Atomic schema-versioned run artifacts

- Run artifacts now declare `schema_version: 1`, use UUID run identity, retain the pipeline stage list separately, and record UTC start/completion timestamps plus monotonic duration. Benchmark `run_number` remains zero-based.
- Metadata includes prompt/schema versions, taxonomy identity, Git revision/dirty state, installed direct-dependency versions, and a SHA-256 configuration fingerprint computed after removing API keys.
- Benchmark and classification filenames contain UTC timestamps and UUID prefixes. A new run never targets an existing artifact, preserving the historical `logs/RUN_0.json` without special-case behavior.
- Checkpoints are serialized to a same-directory temporary file, flushed, `fsync`ed, and atomically replaced. Failed serialization removes the temporary file and leaves the preceding checkpoint parseable.
- README, tracked configuration comments, implementation report, and repository guidance now describe the active reliability behavior and explicitly deferred caching/provenance/concurrency work.
- The completed implementation passes 116 offline tests plus compilation, lock consistency, installed dependency consistency, and whitespace checks before live validation.

### 2026-09-20 — Reliability live validation

- Confirmed the ignored local configuration selects the 39-label hierarchical taxonomy, not the debugger profile's historical “flat” name. The one-CVE classification of `CVE-2021-27103` completed successfully as `SSRF` in 3.08 seconds with no warnings, retries, or repairs.
- The exact authorized ten-CVE artifact `RUN_0_20260920T153302856729Z_5de5c547.json` completed in 200.844 seconds with 7 success, 3 degraded, 0 error, complete 10/10 coverage, and 0.9 exact-match accuracy/micro precision/recall/F1. `CVE-2020-14864` remained the known sole mismatch.
- The benchmark recorded 183 external attempts, one successful NVD transport retry, no repairs, and 546,067 audited tokens. All seven warnings were recoverable reference outcomes: four permanent HTTP 403 responses and three extraction `ValueError`s. No code-caused terminal failure occurred.
- Maximum per-CVE use was 38/100 requests and 189,870/250,000 tokens; run totals were 183/5,000 requests and 546,067/10,000,000 tokens. Audit records contained no prompt, response, credential, authorization, or raw-exception fields.
- The final artifact was complete, parseable, atomically closed, and recorded a clean Git revision. The pre-existing `logs/RUN_0.json` retained SHA-256 `4f039469f7839485a40f7baf61ea1a97424aa810ca156b8e993dd926b45402a9` and was not modified.

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
