# JSON fixtures, benchmark CLI, and live pipeline investigation

Date: 2026-09-19

## Scope

This report covers the migration from hard-coded Python labels and benchmark cases to JSON fixtures, the final command-line behavior, hierarchy-aware classification, result logging, the investigation of the reported HTTP 502, and the performance work prompted by a live run of the first ten flat-fixture CVEs.

The supplied JSON is kept as repository data. Runtime loaders adapt it to the mappings consumed by the existing linear LangChain pipeline, preserving hierarchy and benchmark provenance.

## Fixture migration

The old label and test-case definitions were removed from `src/Definitions/labels.py` and `src/Definitions/const.py`. The supplied pairs now live next to `src`:

| Fixture | Labels | Expected cases |
| --- | ---: | ---: |
| `fixtures/flat` | 9 | 50 |
| `fixtures/hierarchical` | 39 | 50 |
| `fixtures/hybrid` | 84 | 50 |

Each directory contains `taxonomy.json` and `expected-classification.json`. The loaders retain label IDs, names, definitions, parent links, case rationales, and source lists.

`src/Definitions/fixtures.py` now performs validation before any NVD or model client is constructed. It rejects:

- malformed or duplicate label IDs;
- missing definitions and invalid parents;
- unknown parents and hierarchy cycles;
- hierarchy policies other than `most_specific`;
- malformed or duplicate CVE case IDs;
- unknown expected labels, duplicate expected labels, and `NONE` mixed with another label;
- expected ancestor and descendant labels in the same `most_specific` case;
- benchmark files whose `taxonomy_sha256` does not match the selected taxonomy.

The fingerprint is computed from canonical JSON. Whitespace and file formatting therefore do not change the identity of the taxonomy.

## Configuration

The tracked `config.example.toml` now includes:

```toml
[fixtures]
taxonomy_file = "fixtures/flat/taxonomy.json"
expected_classification_file = "fixtures/flat/expected-classification.json"

[classification]
max_input_tokens = 12000
```

`taxonomy_file` is required. `expected_classification_file` is optional and is read only in benchmark mode. Both paths are resolved relative to the repository root, independent of the shell's current directory.

The ignored local `config.toml` was migrated without replacing or exposing its API credentials. The tracked example selects the flat pair and contains placeholders only.

`max_input_tokens` limits the approximate classifier input for each label group. The estimate is:

```text
ceil(1.2 × UTF-8 byte count ÷ 3)
```

It covers the rendered prompt and structured-output schema. If the CVE evidence plus one label does not fit, classification fails before a model call.

## Final CLI behavior

One or more CVE IDs are always required:

```bash
uv run python src/CVE_expert_seq.py CVE-2021-27103 CVE-2024-27443
```

This classifies the requested IDs without loading expected labels or calculating scores.

Benchmarking is optional:

```bash
uv run python src/CVE_expert_seq.py --benchmark CVE-2021-27103 CVE-2024-27443
```

With `--benchmark`, every requested CVE must exist in the configured expected-classification file. Extra cases in that file are ignored. This permits small, repeatable benchmark subsets without editing fixture data.

The CLI rejects missing CVE IDs, duplicate IDs, malformed IDs, a benchmark request without a configured dataset, and benchmark IDs absent from that dataset. These checks occur before client construction and live requests.

## Pipeline integration

The pipeline is built once per invocation with the selected taxonomy. The summarizer receives the root label definitions as broad guidance. The classifier receives every label, including parent context for hierarchical entries.

For a taxonomy too large for one call, labels are split into stable groups under the configured estimate. Every group response is validated. Selected labels are combined and any selected ancestor is removed when a selected descendant exists, including when they came from different groups.

`NONE` is returned only when every classifier group successfully selects no applicable label. A request failure, malformed structured response, or invalid group label remains a terminal classifier error.

## Logs and metrics

Benchmark runs retain the existing `RUN_N.json` naming. Classification-only runs use distinct UTC timestamped `CLASSIFY_*.json` names so repeated ad hoc runs do not overwrite one another.

Benchmark entries preserve expected labels, rationales, sources, individual scores, and aggregate scores. Classification-only entries omit all expected-label and score fields.

Metrics now include exact-match accuracy together with micro precision, recall, and F1. Coverage reports `total`, `scored`, `successful`, `degraded`, `failed`, and `complete`. Successful and degraded results are scored; terminal errors are excluded and make coverage incomplete.

At benchmark completion, the CLI prints a progress-safe aligned table in requested CVE order. Each row contains the status, expected labels, predicted labels, exact-match accuracy, precision, recall, and F1. An aggregate row and a coverage line follow. Terminal failures remain visible with `—` for unavailable scores. Classification-only runs do not print this table.

## HTTP 502 investigation and failure attribution

The reported failure was an HTTP 502 containing an HTML gateway page. It did not recur in the subsequent one-CVE or ten-CVE debugger runs, so the upstream service responsible for that particular response could not be proven from the truncated original output.

The investigation found one application-level problem: `CosineFilterNode` fetched its shared query embedding while the pipeline was being constructed. A gateway error at that point could abort the entire invocation before a CVE existed in the result log.

The query embedding is now requested lazily during filtering and cached only after success. A failed request is recorded as a terminal filter error for the active CVE, and a later CVE can retry. Console diagnostics keep the stage and CVE at the start of the message and reduce an HTML gateway body to a short safe description.

## Timing instrumentation

Live `RunnableSequence` executions now record `stage_timings` in every CVE result. Each entry contains only:

- the top-level pipeline stage name;
- elapsed wall-clock seconds;
- success or error status.

The callback records a failing stage as well. It does not persist prompts, responses, credentials, or callback inputs and outputs. Durations include local processing, configured pacing, network latency, and provider processing, so they locate slow stages without claiming to isolate server compute time.

## Live test method

The first ten cases from the flat fixture were run under `debugpy` with the configured live NVD, page extraction, embedding, and chat services. Both the baseline profile and the post-change rerun used isolated temporary output directories, leaving the user's existing `logs/RUN_0.json` untouched.

The requested CVEs, in order, were:

1. `CVE-2021-27103`
2. `CVE-2024-27443`
3. `CVE-2018-7445`
4. `CVE-2020-14864`
5. `CVE-2021-30632`
6. `CVE-2021-44026`
7. `CVE-2016-9079`
8. `CVE-2020-7961`
9. `CVE-2021-25297`
10. `CVE-2021-27104`

Both complete runs produced 6 successful, 4 degraded, and 0 terminal results. Exact-match accuracy, micro precision, micro recall, and micro F1 were all `0.9`. All predictions were identical between the runs.

The baseline had 18 recoverable warnings and the rerun had 16. Every warning was a scrape-stage `ValueError`. Page availability changed between runs, so this difference is treated as live-web variability rather than an effect of the code change.

## Baseline findings

The baseline took 264.46 seconds across the ten CVEs.

| Stage | Baseline seconds | Share of total |
| --- | ---: | ---: |
| Semantic chunking | 81.84 | 31.0% |
| Summarization | 67.68 | 25.6% |
| Classification | 45.96 | 17.4% |
| Reference extraction | 38.10 | 14.4% |
| Cosine filtering | 20.26 | 7.7% |
| NVD | 10.61 | 4.0% |

Two CVEs accounted for about 54% of the elapsed time:

- `CVE-2020-14864` took 62.25 seconds. One Oracle page contained 126,192 characters and 403 distinct CVE IDs, while the target appeared twice. It produced 159 semantic chunks and 28 retained non-placeholder chunks, but no accepted reference summary. The final result was `AccessControl`; the expected label was `PathAndResourceSelection`.
- `CVE-2016-9079` took 80.38 seconds. Eight target-specific sources produced 194 chunks. Semantic chunking, filtering, and summarization dominated the case.

Classifier latency also varied independently of input size. `CVE-2021-27104`, which had one page and one chunk, still spent 18.13 seconds in classification during the baseline.

## Broad-index focus rule

The Oracle result showed that the semantic splitter and filter were processing a vulnerability catalog rather than a target-specific advisory. A narrow preprocessing rule now runs immediately before semantic chunking:

1. Leave pages shorter than 50,000 characters unchanged.
2. Leave pages with fewer than 100 distinct CVE IDs unchanged.
3. Leave a broad index unchanged if it does not contain the requested CVE.
4. Otherwise, retain 2,000 characters on each side of every requested-CVE occurrence and merge overlapping spans.

The complete extracted page remains in `nvd_references_pages` and in the JSON run log. Only downstream chunking uses the focused text. Future run logs add `reference_focus` with original and focused character counts when the rule applies.

Offline tests cover a large multi-CVE index, a long target-specific technical page, an index without the target, preservation of the original page in state, use of the focused text by the semantic splitter, and persistence of focus metadata in the result log.

## Performance result

An isolated rerun of `CVE-2020-14864` reduced its elapsed time from 62.25 to 8.26 seconds and its chunk count from 159 to 3. In the complete post-change run it took 6.14 seconds. The prediction remained `AccessControl`, so the existing benchmark mismatch was unchanged.

The complete post-change run took 204.64 seconds, a reduction of 59.82 seconds or 22.6%.

| Stage | Baseline | After | Difference |
| --- | ---: | ---: | ---: |
| Semantic chunking | 81.84 s | 63.29 s | -18.55 s |
| Summarization | 67.68 s | 44.41 s | -23.27 s |
| Classification | 45.96 s | 28.86 s | -17.10 s |
| Reference extraction | 38.10 s | 41.92 s | +3.82 s |
| Cosine filtering | 20.26 s | 17.35 s | -2.91 s |
| NVD | 10.61 s | 8.79 s | -1.83 s |
| **Total** | **264.46 s** | **204.64 s** | **-59.82 s** |

`CVE-2020-14864` accounts for 56.11 seconds of the total reduction. Changes in other stages and CVEs include network, page, pacing, and provider variability. The unchanged predictions and metrics are evidence that this ten-case subset did not regress, but they are not a general quality guarantee for every broad index.

The focus rule removed all non-placeholder filtered chunks for the Oracle page in this run. The baseline also produced no accepted summary from that page, so classification context and the prediction were unchanged. This remains the main quality risk of the optimization and is why the rule is limited to unusually large multi-CVE indexes while retaining the full source page for audit and future reprocessing.

## Remaining bottlenecks and problems

### `CVE-2016-9079` remains expensive

The post-change case took 87.24 seconds: 38.48 seconds in semantic chunking, 10.35 in cosine filtering, and 26.69 in summarization. Its sources are target-specific, so the broad-index rule correctly does not shorten them.

### Two embedding passes process the same source material

The semantic splitter embeds page segments to find boundaries. The cosine filter then embeds the resulting chunks. The inputs are not identical, but large pages incur two embedding-heavy passes. Reusing compatible vectors or moving to one embedding pass could reduce the largest remaining local request volume, but it needs benchmark-quality evaluation because it changes retrieval behavior.

### Work is sequential and uncached

CVEs, page downloads, chunking, filtering, and per-reference summaries are processed sequentially. There is no persistent NVD, page, chunk, embedding, summary, or model-result cache. Repeating a debugger run therefore repeats all live cost and inherits service variability.

The safest next operational improvement is a versioned cache or replay artifact with explicit stage compatibility. It would make performance and quality comparisons reproducible before adding concurrency.

### Reference acquisition is variable

The two runs produced 18 and 16 scrape failures, and one CVE exposed a different number of usable pages. The scraper has no project-level retry policy or persistent page cache. Structured warning counts make the failure visible, but a retry and timeout policy would improve stability.

### Provider latency is variable

Small inputs can still have long model latency, as shown by the 18.13-second baseline classification for `CVE-2021-27104`. Stage timing identifies this behavior but cannot distinguish queueing, retry delay, pacing, and provider compute.

### The one remaining classification mismatch lacks technical evidence

`CVE-2020-14864` remained `AccessControl` instead of the expected `PathAndResourceSelection`. Both runs ended without an accepted external summary, leaving a generic NVD description centered on unauthorized access. The current evidence supports investigating reference selection, filtering, or summarization before changing the taxonomy or classifier prompt.

## Verification

The final offline checks completed without live requests:

- 88 `unittest` tests passed;
- Python compilation passed for `src` and `tests`;
- `uv lock --check` passed;
- `uv pip check` found the environment compatible;
- `git diff --check` passed.

Coverage includes all three supplied pairs and their 9, 39, and 84 labels and 50 cases, canonical fingerprint mismatches, malformed hierarchies, CLI modes and errors, bounded grouping, ancestor removal across groups, `NONE`, terminal failures, mode-specific logs and scores, lazy query-embedding retry, stage timings, and the broad-index focus behavior.

## Debugger configuration

`.vscode/launch.json` contains a launch configuration named `Benchmark: first 10 flat CVEs` with the ten IDs listed above and `--benchmark`. It uses the repository `.venv`, runs from the workspace root, and remains ignored and uncommitted as requested.

## Commit breakdown

The work was divided into cohesive commits:

| Commit | Logic unit |
| --- | --- |
| `b4ecb25` | Add the three supplied JSON taxonomy and benchmark pairs. |
| `eb7b49a` | Load and validate taxonomy hierarchy, cases, provenance, and canonical fingerprints. |
| `e1bf4b5` | Integrate JSON configuration, grouped hierarchy-aware classification, and mode-specific execution/logging. |
| `f05150c` | Document the fixture and CLI architecture. |
| `fb93177` | Require explicit CVE IDs and score optional benchmark subsets. |
| `f41f0f5` | Attribute query-embedding gateway failures to CVE runs and improve safe diagnostics. |
| `13e717e` | Add per-CVE pipeline stage timings. |
| `980ad6c` | Focus broad multi-CVE indexes before embedding and record focus metadata. |
