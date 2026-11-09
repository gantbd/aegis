# Operating rigor

- Identity, authentication evidence, authority, visibility, and attribution remain
  separate types and decisions.
- Actions and resource scopes are closed, bounded, and versioned; executable
  `Unknown(String)` permission escape hatches are forbidden.
- Delegation is checked by an explicit subset relation and bounded ancestry.
- Time, epochs, identity issuance, and randomness are explicit inputs.
- Refusal occurs before mutation or opaque-grant publication.
- Revocation changes current authority but never erases history or undiscloses data.
- Debugging, metrics, and errors redact grant material and credential evidence.
- A test credential fact proves only the scenario premise, not real authentication.
- Security claims require adversarial tests and a declared host boundary.

