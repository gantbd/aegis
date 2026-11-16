# Compatibility profile

Status: package/source topology and canonical empty/live V1 checkpoints frozen;
cross-version compatibility qualification still open.

`make check-compatibility-baseline` refuses unreviewed package-name, version or
manifest-path drift against `compatibility-baseline.txt`. The current canonical
empty and live-frontier checkpoint fixtures are external, digest-pinned and
consumed by the recovery tests.
Until a broader valid/invalid corpus is exercised across released versions, this
repository makes no general upgrade or downgrade compatibility promise.

`aegis-unix-peer` adds a bounded deployment mapping and a namespaced monotone
session allocator. Mapping configuration and session namespace are source-level
V1 inputs; no credential file or wire format is defined.

`aegis-witness` compares the exact opaque checkpoint revision and bytes. Its V1
decision algebra and fail-closed ordering are source contracts, but it defines no
external witness wire format or storage schema.
