# Matcher module (Asmita)

The GPU half of the project: turn attack signatures into an automaton, scan
payload bytes against it on the GPU, and report both the matches and how much
work each segment took.

## Build and run

```bash
make test      # CPU reference tests — run anywhere, no GPU
make gputest   # CPU vs GPU diff — needs nvcc and a GPU
```

No GPU on your laptop: open `notebooks/gpu_test.ipynb` in Colab, set the
runtime to **T4 GPU**, and run the cells.

## Files

| File | What it does |
|---|---|
| `include/ids_types.h` | The structs shared with Ananyaraj and Ananya Das. Do not change alone. |
| `src/rules.cpp` | Pulls `content:"..."` patterns out of Snort/Suricata rules, including `\|90 90 90\|` hex. |
| `src/pfac.cpp` | Builds the goto trie and flattens it into a dense table the GPU indexes. |
| `src/cpu_match.cpp` | Single-threaded reference matcher. Ground truth for the diff. |
| `src/gpu_match.cu` | The PFAC kernel: one thread per byte, plus per-segment cost. |
| `tests/test_cpu.cpp` | Unit tests for parsing, building, matching and carry de-duplication. |
| `tests/test_gpu.cu` | Runs both matchers on the same batch and diffs the results. |

## What I hand the others

**To Ananya Das**, per batch:
- `Match[]` — every signature hit, as `(seg_idx, pos, sig_id)`
- `unsigned long long[]` — one step count per segment; this is the cost signal
  the predictor learns from
- `PfacTable.max_pat_len` — the `L_max` that sets the tail-carry length

**From Ananyaraj**: a byte arena plus a `Segment[]` pointing into it.

## Two rules I have to keep

**The carry rule lives in two places.** `carry_keeps_match()` in
`cpu_match.cpp` and `d_carry_keeps_match()` in `gpu_match.cu` must stay
identical. If they drift, the alert-set diff fails and the project's
correctness claim goes with it.

A match starting inside the carried prefix was already reported by the previous
segment if it also *ended* there:

```
pos + pat_len <= carry   ->  drop (previous segment already saw it)
pos + pat_len >  carry   ->  keep (it crosses the cut, nobody else sees it)
pos >= carry             ->  keep (our own bytes)
```

**The kernel does not get optimised to make numbers look better.** PFAC is
fixed, from Lin et al. (2013). If I change the matching algorithm partway
through, the baseline and the adaptive runs stop being comparable and the whole
result means nothing.

## Known limits (state these in the report, do not hide them)

- Only `content:` patterns are used. `pcre:`, `byte_test:`, `distance`/`within`
  and negated content are skipped; the parser counts how many.
- A rule with several `content:` strings becomes several independent patterns.
  We match patterns, not full rule semantics.
- The transition table is dense: `num_states × 256 × 4` bytes. Roughly 40 MB for
  2,000 ET patterns, which fits a T4 comfortably. Bellekens et al. compress
  this; we deliberately do not, because our contribution is scheduling.
- `nocase` is ignored. Adding it means lowercasing both patterns and payload,
  which changes measured cost, so it is a decision for the whole team.

## Next

1. Run `make gputest` on Colab and confirm the match sets are identical.
2. Record the warp efficiency number on an unbalanced batch — it is the
   "before" figure in the results table.
3. Hand Ananya Das the `seg_cost` array and agree how often she wants it back.
