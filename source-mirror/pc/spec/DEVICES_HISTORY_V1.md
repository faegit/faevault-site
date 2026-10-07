# Device activity and encrypted local history v1

User authorized implementation after remote reminder completeness review on 2026-10-07. No own server required.

## Authenticated device records

Vault metadata `_device_activity_v1` contains version=1, profiles with real device_identity UUID (not sync_meta vault-lineage device_id), optional user name up to64 characters, platform android/pc, last_seen_at and updated_at epochmilliseconds. Unknown fields remain intact. Current client stamps device activity during actual durable saves. Profiles merge deterministically per identity with explicit nickname revision; existing signed authorization registry remains authoritative for grant status. Current-device rename is supported; no claim that removing a row revokes server access.

Last writer `{device_id,updated_at,parent_commit_id}` is stored in the same encrypted authenticated Commit. Parent is the authenticated head ID before that write. Reader must compare it to the authenticated resulting Commit parent and resolve a known device profile. Missing, invalid, unbound, mismatched or old-client-carried records show unknown. Notification HEAD-only detection never guesses the writer. Device information is shown after authenticated remote preview, alongside its checked version/time.

## Local encrypted version history

Immutable complete PMVE file snapshots retain media Objects and Header/key state. Store in app-private per-vault UUID folders with protected index, pinned SHA-256 and authenticated identity. Retain20 regular versions plus at most2 pre-restore safety versions; temporarily retain an in-use source until restoration commits. Deduplicate the same commit and signing-key epoch; password rotation must not reuse an incompatible old-key safety snapshot. Explicit capture reports failure; best-effort automatic before durable mutation may not abort normal save. Never store plaintext passwords/entry contents in a history index. Reject symlinks/path traversal/tampering/cross-vault snapshots; deletion/retention never escapes the archive directory.

Authenticated read-only previews expose active entry titles/accounts/counts, mask secrets and permit explicit old-password authentication when rotation made current credentials unusable. Preview keeps exact archive fingerprint and expected current head. Restore is selective: selected active historic entries become new local changes with timestamps strictly newer than current/historic versions. Current entries outside selection and current recovery/security metadata/device authorizations stay intact. Before restore, require a separate current recovery snapshot; abort stale selections/current-head conflicts without overwrite. Import reachable media Objects atomically through existing authenticated merge writer. The initial selective restore excludes all Passkey-bearing entries to prevent credential counter rollback and reconstruction of non-exportable hardware private keys; it also refuses current permanent-purge tombstones. Other historical entries and reachable media restore as new changes.

## UI

Devices/history page is accessible without cloud configuration. Show current device, record name/platform/activity and verified authorization state; edit current nickname. History list allows create, select, async preview, checkbox entry selection, guarded confirmation and explicit success/error. Device-bound unavailable credentials are labeled; no silent destructive whole-file rollback. Bilingual theme-aware existing controls are reused.

## Verification

Shared device_activity_v1_fixtures.json checks parent binding, old-client stale records, absent data and unknown identity. Tests must cover immutable/tampered snapshots, retention/dedup, old credentials, cross-vault rejection, stale head/preview, selective restoration preserving new entries/security, and image/media reachability after compaction. Separate physical notification and real storage-provider tests remain external.

Implemented behavior: metadata-only system notifications stay generic. Authenticated remote preview displays the matching content writer; a newly observed version invalidates cached writer details. Android preview models strip passwords, notes and extension fields before entering Compose. PC Qt previews carry only IDs, titles and usernames. Current-vault head approved at preview is frozen across the confirmation/password retry. Private pins use Keystore/protected config; hashes stream rather than load entire files. Archive writes lock the source across copy and protected index publication. Cancellation/session changes are checked before restore writes. Independent read-only review found no remaining confirmed restore/data-loss blocker after repairs.
