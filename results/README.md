# Benchmark results

Reports written by `purplemcp bench` (see
[docs/07-research-methodology.md](../docs/07-research-methodology.md)).

- [`guardrail-benchmark.md`](guardrail-benchmark.md) / `.json` — a committed
  **reference run** of the deterministic guardrail-effectiveness benchmark (M1).
  Reproduce it with:

  ```bash
  purplemcp bench --save --out results
  ```

Timestamped runs (`bench-*.json`, `bench-*.md`) and model-susceptibility runs are
git-ignored — regenerate them locally. The deterministic M1 result should match
the committed reference on any machine; the optional model run (M2) varies by
model and seed by design.
