# FAEVault Security Whitepaper Rewrite Design

## Goal

Rewrite the complete Chinese and English security whitepaper from the current Android implementation. The page must distinguish implemented protection, configurable behavior, trust assumptions, and out-of-scope threats. It must not claim planned, inferred, or desktop-only behavior as an Android capability.

## Audience and reading model

Use a layered structure for both ordinary users and technical readers:

1. A short plain-language security position and “what this document covers”.
2. Threat model and explicit boundaries before cryptographic detail.
3. System architecture and data lifecycle in readable sections.
4. Exact technical parameters and implementation details where they materially support a claim.
5. Operational guidance and limitations, without marketing absolutes.

Chinese is the source meaning. English must be a faithful equivalent, not a looser marketing rewrite.

## Source of truth

Every factual statement must be traceable to the current Android checkout under `D:\Mine\Projects\demo\vault_android`, especially:

- `crypto/PmvKdfPolicy.kt`, `crypto/PmvKeySchedule.kt`, and `crypto/RecoveryKeyCodec.kt`
- PMV container, header, block, attachment, integrity, backup, and repository code under `storage/`
- `security/BiometricVault.kt`, `VaultSessionCredential.kt`, `LockoutPref.kt`, `WindowSecurity.kt`, and secure preference/session helpers
- autofill and passkey packages
- LAN/WebDAV/cloud sync implementations
- Android manifest and backup/data-extraction rules

Comments are supporting context only. Executable behavior and tests take precedence when comments are stale. A known example is the old biometric comment that mentions wrapping the master password, while the current PMVE path stores a vault-bound RootKey unlock material.

## Page structure

### 1. Security overview

State the design objectives: local-first encrypted storage, authenticated encryption, purpose-separated keys, explicit unlock gates, encrypted sync payloads, and no claim of perfect security.

### 2. Threat model and boundaries

Cover protected scenarios such as stolen vault files, accidental corruption, untrusted storage providers, and unauthorized app requests. Clearly exclude or qualify compromised/rooted devices, malicious keyboards, screen observation when protection is disabled, unlocked sessions, weak master passwords, exposed recovery/export credentials, and traffic metadata.

### 3. Cryptographic architecture

Explain the PMVE/PMVS container, Argon2id v1.3 profiles and accepted bounds, the random 256-bit Vault RootKey, AES-256-GCM envelopes and blocks, HKDF-SHA256 domain separation, per-object/per-generation/per-chunk keys, nonces, AAD, authenticated headers, integrity keys, and Ed25519 signing identity where used by the format.

### 4. Unlock and key lifecycle

Describe password unlock, password changes as RootKey rewrapping, the 256-bit recovery secret and checksum encoding, recovery-slot behavior, in-memory session material and wiping, persistent unlock cooldown, and biometric unlock using AndroidKeyStore with `BIOMETRIC_STRONG`, enrollment invalidation, and vault identity binding.

### 5. Data storage and large objects

Describe append-oriented immutable blocks, indexes/commits/tombstones, authenticated metadata, attachments split into encrypted chunks, integrity verification, bounded/lazy access where supported, and the practical distinction between encrypted content and observable file-level metadata.

### 6. Android platform protections

Cover app-private storage, disabled Android backup/device transfer, configurable `FLAG_SECURE`, recent-task hiding as a separate option, sensitive clipboard marking and configurable clearing, reauthentication gates, and the limitations of each control.

### 7. Autofill and passkeys

Separate Android Autofill from Credential Manager passkeys. Document per-operation user verification, package/host association and certificate checks, rejected sensitive callers, WebAuthn origin/RP validation, supported signing behavior, and key storage/backup modes only when directly confirmed in code.

### 8. Sync and remote storage

Separate LAN sync, WebDAV, and cloud sync. Explain that encrypted vault data is transferred, local merge/re-encryption behavior, SPAKE2-P256 or certificate pinning where actually applied, downgrade prevention, post-transfer verification, and what endpoints can still observe.

### 9. Export, backup, and recovery

Explain the security properties of `.pmv`, encrypted `.pmbak`, other exports, external real-time backups, credential responsibility, and destructive/recovery boundaries. Avoid implying that every export format is encrypted.

### 10. Security guidance and honest limitations

Give actionable advice: strong unique master password, offline recovery-key storage, protected devices, updated OS, trusted sync endpoints, and careful handling of exports. End with a concise non-audit statement and a version/source snapshot note.

## Presentation design

Replace the current uniform card wall with a document-like page:

- A compact summary panel near the top for implemented security pillars.
- A readable single-column narrative for core sections.
- Small technical fact tables for algorithms, parameters, and boundaries.
- Callouts for “protects against”, “does not protect against”, and user-controlled options.
- Stable anchor IDs and a compact table of contents.
- Mobile-first typography without narrow two-column cards that fragment long explanations.

The page remains visually consistent with the existing journey theme and does not introduce unrelated imagery.

## Verification

- Re-check each mechanism against current Android code before writing its final copy.
- Keep Chinese and English section order and factual scope identical.
- Add/update content tests for critical algorithm names, security boundaries, and bilingual parity.
- Run the website test suite and production build.
- Inspect both language pages at desktop and mobile widths for overflow, title wrapping, navigation, and readability.
- Review the final diff to ensure unrelated worktree changes are untouched.
