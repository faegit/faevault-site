# FAEVault pc source-review snapshot

Snapshot date: 2026-10-09. Application version: 4.6.8.

Original FAEVault source in this snapshot is provided under Apache-2.0.
Retained upstream notices and Microsoft sample files keep their own licenses.
See LICENSE, NOTICE and OPEN_SOURCE_REVIEW.md for the selection policy.

This is a reviewed source snapshot, not the complete private repository or a
reproducible signed application distribution. Signing keys, user data, private
audit evidence, third-party binary bundles, icons, fonts, dictionaries and other
assets with incomplete provenance are intentionally omitted. UI code references
some omitted assets; do not expect a full app build or every UI test to run.

Cryptographic test keys and passwords in the included fixtures are synthetic
public test data. They must never be used as production credentials.

PC shared-vector tests can use VAULT_SHARED_SPEC_DIR=./spec. Python dependencies
are declared in pyproject.toml and uv.lock; Qt and other libraries keep their
upstream licenses and are not bundled here.
