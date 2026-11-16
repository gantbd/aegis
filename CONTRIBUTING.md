# Contributing to Aegis

Aegis is source-distributed and has not made a production release. Preserve the
authority boundaries and nonclaims in `docs/release-policy.md`,
`docs/release-readiness.md`, and `SECURITY.md`.

The repository targets the Rust toolchain pinned by `rust-toolchain.toml` and
uses the exact Keystone source revision recorded in
`release/github-source.json`. Run the complete gate before submitting changes:

```sh
make check
```

The process and Unix-socket tests require an environment that permits local
subprocesses and Unix-domain sockets.

- Keep every crate non-publishable unless the release policy changes in the
  same reviewed contribution.
- Preserve explicit bounds, typed uncertainty, opaque authority handles, and
  content-safe diagnostics.
- Treat compatibility fixtures, attestations, traceability records, and release
  profiles as source artifacts.
- Do not commit credentials, private user data, local paths, or build output.

Report suspected vulnerabilities through `SECURITY.md`, not a public issue.
