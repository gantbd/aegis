# Traceability ledger

| Requirement | Planned implementation | Current evidence | Status |
| --- | --- | --- | --- |
| A1 identity separation | fixed-width distinct IDs, opaque grant, explicit decision evidence | issuance/validation scenarios | Satisfied for volatile profile; credentials external |
| A2 scopes | closed namespaces/actions and finite `ActionSetV1` lattice | bounded-lattice laws and authorization scenario | Satisfied for represented actions |
| A3 delegation | subset/expiry/depth-monotone attenuation | action and expiry amplification refusal scenarios | Partial; ancestry persistence open |
| A4 revocation | monotone authority epoch | old-grant rejection after epoch advance | Satisfied for global volatile epoch |
| A5 opacity | private non-cloneable `GrantV1` construction | public API and validation-by-grant behavior | Satisfied for safe Rust API |
| A6 atomicity | validate before identity publication | refusal scenarios and strict lint | Partial; broader saturation evidence open |
| A7 bounds | scope and delegation-depth limits, checked identities | constructor and implementation evidence | Partial; state persistence open |
| A8 explicit time | caller-supplied issue/attenuate/validate time | expiry/attenuation behavior | Satisfied |
| A9 privacy | opaque IDs and redacted grant/decision debug | redaction assertion | Satisfied for implemented surfaces |

