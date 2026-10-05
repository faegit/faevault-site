# FAEVault source publication review

Reviewed snapshot: 2026-10-05. Android and PC application version: 4.6.6.

## Published scope

The owner selected Apache-2.0 for original project source. The Android snapshot includes Kotlin application and UI code, cryptography, PMVE storage, data models, LAN/cloud synchronization, password cooldown, Autofill and Credential Manager/Passkey implementations, tests, XML declarations and dependency/build declarations. The PC snapshot includes Python core and UI source, browser autofill extension text source, Windows native passkey provider source, dependency declarations and tests. Audited shared specification and interoperability fixtures accompany both snapshots.

These implementations are useful for independent security review and interoperability development. Publishing cryptographic algorithms does not require publishing user keys. No confirmed live credential was identified in the selected current files during this review; this is not a guarantee of correctness or a review of private Git history.

## License boundaries

Original FAEVault source is Apache-2.0. Existing upstream notices remain effective. The Windows provider contains Microsoft sample-derived code whose MIT license is retained. Android dependency notices are included. Python/Qt and other dependencies retain their own licenses, including applicable Qt distribution requirements; they are not included as binary libraries here.

## Excluded material

Signing keystores, certificates and passwords; real vaults, account configuration and user databases; repository history; build output, downloaded dependencies and caches; private security audit evidence and red-team material; deployment/install scripts containing personal paths. Packaged icons, fonts, Mermaid/KaTeX bundles, dictionaries, bank data and other assets whose provenance or license mapping has not been fully recorded are withheld from this initial mirror.

Only four specifically audited PMVE interoperability blobs are included. Test passwords, tokens and keys in synthetic fixtures and the demo generator are deliberately fictional public test material and must never serve as production credentials.

## Reproducibility and verification

This is a selected source-review snapshot, not a complete buildable application repository or a signed release. UI and application builds may refer to omitted assets. Each platform MANIFEST.json records source revision, snapshot date and per-file SHA-256. The exporter uses a path allowlist, rejects symlinks and credential-shaped literals, verifies original source stability and verifies downloaded archive inventories and bytes. Source revisions describe the base revision; current working-tree contents are captured and authenticated by the per-file hashes.

The ZIP archives and browsable mirrors contain the same platform files. Public download metadata and SHA256SUMS.txt authenticate the archives. PC shared-vector tests can point VAULT_SHARED_SPEC_DIR to its bundled spec directory. These checks establish publication integrity; they do not establish the absence of security defects in the application.
