# Performance qualification

`make performance` runs an ignored optimized acceptance test for the selected
receipt-gated in-memory authority profile. The target records the Rust compiler,
OS and architecture, then measures 64 successful samples each of grant issue,
authorization, epoch revocation, and durable-checkpoint recovery with mandatory
epoch advancement. Setup and compilation are outside the samples; every measured
operation retains its functional assertions.

The provisional reference-host engineering budgets are p95 <= 10 ms and sample
p99 <= 25 ms for each operation class. With 64 samples nearest-rank p99 is the
maximum, not a statistically established production tail. On 2026-11-10 the
`aarch64-apple-darwin` Rust 1.95.0 optimized run produced:

| Operation | p50 ns | p95 ns | sample p99/max ns |
| --- | ---: | ---: | ---: |
| Issue | 167 | 250 | 7,584 |
| Authorize | 125 | 208 | 16,208 |
| Revoke epoch | 166 | 167 | 458 |
| Recover and advance epoch | 125 | 208 | 458 |

This is a regression gate for the exact synthetic profile, not a product SLO.
The in-memory receipt store performs no filesystem sync. The population excludes
daemon transport, authentication, concurrent clients, large authority sets,
allocation/RSS, power loss and external rollback witnesses. Durable filesystem
and process-soak qualification remain separate release work.
