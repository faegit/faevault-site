---
title: "Changelog"
description: "FAEVault Android changelog"
locale: en
translationKey: changelog
order: 0
---

# FAEVault Android Changelog

This changelog records features and fixes for the FAEVault Android client only. Desktop changes are maintained in their own repository.

---

## 4.6.1 - 2026-09-23

### Added
- Offline scanning: document edge detection and perspective correction now use OpenCV, and QR capture uses CameraX + ZXing — the **Google document-scanner and Code Scanner dependencies were removed** (no GMS device required; scanning stays entirely on-device).
- Image blur: new "Images" setting; entry thumbnails and image previews are blurred by default and the original is shown only after the required verification.
- Tags: batch add now supports multiple tags (parsing Chinese/English commas, spaces and newlines).
- Card dates: normalised input and display (`YYYY-MM-DD` / `MM/YY`) plus a stored "long-term" sentinel.
- Password health: weak passwords are now judged by zxcvbn scoring.
- Scrolling: a visual edge bounce replaces the platform stretch effect.

### Improved
- Capture quality: switched to `CAPTURE_MODE_MAXIMIZE_QUALITY` (the previous mode skipped 3A convergence and often captured unfocused frames); 4:3 is pinned with a higher-resolution preference; the crop source cap went 1800 → 3000; the review-screen output is no longer re-compressed.
- Camera zoom buttons are anchored to the bottom edge of the preview image, inside the frame instead of on the black bar.
- Secondary-page titles are now centred; the security list's count moved to its own line in the same colour as the title; the help icon gained its trailing margin and a larger touch target.
- Background-task notifications stay visible at all times instead of being withdrawn when the app enters the foreground; terminal notifications also appear in the foreground.
- Clipboard: overdue sensitive content is swept when the app returns after process death; the clear delay is configurable (0–600 s, `0` = never).
- Bottom navigation label 「库维护」 renamed to 「整理」.

### Fixed
- Bottom sheets (app picker / fill picker / module picker) were painted at the top of the screen instead of as bottom cards.
- Storage: merge write-back now streams and reuses the source container instead of rewriting it wholesale; a read-only object manifest descriptor was added.
- Security (per-item status in `SECURITY_AUDIT_2026-09-23.md` section 0): the external-action flag could bypass auto-lock permanently; cross-account pending import was not bound to a target vault; CSV formula injection; WebDAV credentials entered saved state; the WebDAV client cache key held a plaintext private key; dependency-repository boundary.
- Build: `gradle/verification-metadata.xml` was missing two checksums, which made online builds fail unconditionally; `org.gradle.jvmargs` raised from 2g to 4g (release packaging OOMs when run in the same invocation as tests).

### Removed
- Deleted the `docs/` directory (43 plans and design notes) and stray repository logs; removed the outdated cross-platform icon spec and OTP spec (`spec/icons/`, `spec/OTP_SPEC.md`).

---

## 4.5.0 - 2026-09-14

### Added
- Autofill exclusion entries are written into the PMV vault, so they travel with the vault on export, sync, and migration, and are restored after import.

### Improved
- Normal dialogs regain the full-window background blur and dimming shared with the recycle bin, covering the bottom navigation area and the layout after the keyboard collapses; autofill dialogs stay unchanged.
- Home add buttons and pickers align to the right edge with 8dp spacing; the picker's vertical scroll hint keeps a fixed spacer.
- The target horizontal coordinate of home category reorder animations is clamped within the left/right safe-area margins, avoiding the card sticking to the left edge when released.
- The update card swaps content between version notes, download, verification, install permission, and error states and re-lays out, preventing overlapping text and progress bars.
- PMV imports now check readability, size, format, and redundant file headers before account naming; invalid or duplicate names keep the naming dialog open and show an error.
- Username menus size to their content; the switch-user menu is at least as wide as its button; shared dropdown menus cap at 360dp and the switch-user menu at 320dp.
- Unified popup card templates, background blur, close buttons, and scroll-hint effects.
- Improved home category card ordering, single-column floating margins, and right-aligned add FAB / dropdown picker.
- Unified heights for secondary-page add buttons and bulk-action bars; the tag action menu sizes to its text.
- Database temp-file cleanup and PMVE compression are now maintained automatically in the background; the manual cleanup entry was removed.
- Cancelling cloud auto-sync now correctly finishes the pending callback; foreground sync keeps the silent status notification, preventing a hung upload/readback flow or a vanished status.
- Polished the image viewer entrance animation, unchanged-since copy, and more-actions wording.

---

## 4.1.0 - 2026-08-29

### Added
- In-app updates: "Download update" on the About page downloads the APK inside the app, verifies the signature and version, then upgrades through the system installer instead of opening a browser; the first use requires allowing "Install unknown apps" in system settings.
- Markdown rendering upgraded to a full-document WebView: offline rendering supports Mermaid flowcharts/sequence diagrams and other diagrams; the renderer sanitizes HTML and restricts script origins and remote requests to prevent injection and external calls.
- Markdown viewer refactored: styles and interactions extracted into standalone assets (markdown.css / viewer.js) loaded via WebViewAssetLoader on an https same-origin basis; Mermaid diagrams get per-diagram containers (mermaid-card) with toolbars (fit / reset / fullscreen); scrolling-first gestures on body text (single-finger scroll when not zoomed, two-finger pinch, double-tap zoom; single-finger pan after zoom); diagrams can enter native fullscreen; code blocks get one-tap copy (honoring the clipboard TTL auto-clear); wide tables scroll horizontally.
- Markdown viewer scope simplified: only headings / text formatting / lists / task lists / tables / quotes / code blocks / images / Mermaid and internal navigation (auto TOC + #anchor in-page jumps) are supported; external URLs, mail, phone, file paths, cross-document links, and custom schemes are ignored without navigating (vault content never leaves the device).
- Fixed Mermaid diagrams not rendering: the code-block copy button injection polluted the diagram source and broke parsing; Mermaid blocks are now skipped.

### Improved
- One-time codes (OTP) cache derived results per time window, avoiding per-second decryption and HMAC work that stalled the UI.
- The autofill source list is memoized against vault content references, so input and sync heartbeats no longer trigger full-vault decryption.
- Breach-check full-vault decryption moved off the main thread to an IO thread; unlock and manual checks no longer freeze the UI.

## 4.0.0 - 2026-08-14

### Added
- New-generation PMVE encryption container: incremental commits, block-level encryption, object indexing, object-based media and attachment storage, automatic compression, large data and huge file support, with integrity checks.
- LAN communication upgrade: Spake2 mutual authentication, QR / PIN / certificate-fingerprint verification, transfer station auto-detects connection type (import confirmation / sync / file transfer).
- Cloud sync with two independent targets: cloud drive and WebDAV link independently, each with its own auto-sync interval and failure counters.
- Local backups: choose a local directory or external USB drive / hard disk, with scheduled overwrite (from real-time to monthly); target drives are identified by unique device identity to prevent accidental overwrites after drive-letter changes.
- Recovery key and password-reset flow reworked: recovery keys can be re-issued and saved; after verification the app unlocks immediately and enters the change-password flow; the old key stays valid until the new key is confirmed.
- Full English and Chinese UI coverage: hardcoded strings migrated to standard Android resources, taking effect immediately on language switch.

### Improved
- Autofill: indexed matching, app-name fallback display, password generation and fill when no match exists, Inline Autofill compatibility fallback.
- Markdown module: multiline text upgraded to Markdown with full-format rendering, edit/view toggle, formatted view on the detail page, and one-tap copy.
- High-resolution image viewing: screen preview + visible-region decoding, double-tap two-level zoom, multi-image swipe, memory-controlled for very large images.
- Security settings: screenshot protection and background UI hiding split into separate switches; sensitive-operation windows always keep FLAG_SECURE.

### Fixed
- Cloud auto-sync switch being overwritten by another target's polling / shared configuration.
- Copy-sensitive-content prompts not switching with the language.
- ID-type dropdown still showing Chinese after language switch.
- Unlock success animation replaying the ring fill.
- Losing detail-page images after importing many images / attachments, and misaligned placeholder text.
- LAN import / sync / file-transfer connection validation, timeouts, and result dialogs.

## 3.7.0 - 2026-08-02

### Added
- Autofill save requests survive the target app being reclaimed by the process during submission and continue after restoration.
- LAN file transfer can receive files, images, and other attachments and persists them.
- Transferred text is named by send time, format `message_YYYYMMDD_HHMMSS.txt`, for easy time-based lookup and grouping.

### Improved
- LAN transfer receive directory renamed from `FAEVaultshare` to `Vaultshare` for a cleaner path.
- Removed the "End transfer" button in the LAN transfer dialog; the dialog title bar's close button now ends the transfer.

## 3.6.5 - 2026-07-26

### Added
- Completed English UI coverage, including sync, security, maintenance, bank-card editing, biometrics, and recovery-key flows.
- App language selection in Appearance settings on Android 13 and later: follow system, Simplified Chinese, or English.

### Improved
- English app name unified to FAEVault; the Chinese name stays "保险库".
- Shortened the English maintenance navigation name to "Tools" and completed English time units for all interval sliders.
- Login entry tags no longer show an extra `#` prefix.
- Removed the first-launch batched permission requests for camera, gallery, location, and nearby devices; related permissions are now requested per feature when used.

### Fixed
- English security overview still showing the Chinese word "安全" for health status.
- Same-service handling potentially including Passkey or non-login entries; the feature now applies only to login entries.
- Bank-card editing page, auto-sync status, and next-run time retaining Chinese after language switch.

## 3.6.4 - 2026-07-24

### Added
- WebDAV create-directory switch now off by default, avoiding extra directory levels.
- Auto-sync supports independent drive + WebDAV dual targets with separate configs, schedules, and failure counters.
- Cloud sync page (drive / WebDAV) "upload overwrite / download overwrite / relink / unlink" buttons folded into a collapsible "more actions" area to reduce default visual clutter.

### Improved
- WebDAV upload-overwrite uses a temp-file + atomic-move strategy, falling back to direct write and temp cleanup on move conflicts.
- WebDAV conflict detection adds a byte-level SHA-256 fallback (comparing actual content when ETag is unchanged) to avoid false positives.
- Auto-sync scheduler refactored to iterate both targets in a loop; the "skip when cloud sync is running" check moves inside each loop.
- Switching auto-sync targets in settings restores that target's saved interval and switch state.
- Adjusted cloud section spacing in settings with separators between blocks.
- `saveAutoSyncPrefs()` split out of `saveAutoSyncSettings()` to allow persistence without a VM callback.

### Fixed
- Auto-sync pausing the whole feature instead of the failing target after three failures.
- Auto-sync `load()` falling back to old keys when the new per-target keys are missing, so 3.6.3 → 3.6.4 upgrades keep configuration.
- `put()` If-Match header handling of non-HTTP-standard ETags (such as `*`).
- `CloudCredentialStore.createDirectories` default `true` → `false` matching the UI switch.
- Auto-sync `runAutoCloudSyncIfDue` could miss a check because the `cloudSyncRunning` check moved too early.

## 3.6.3 - 2026-07-23

### Added
- Android 14+ Credential Manager Passkey Provider completes create and assertion, with system embedded verification and strong-biometric fallback verification.
- Passkeys saved, counted, and synced as a standalone cross-device entry type instead of borrowing the login credential type.

### Improved
- Existing entries with a "login + Passkey module" auto-migrate to a read-only Passkey type; they remain viewable, deletable, and syncable.
- Passkey requests bind the caller, relying party, credentials, and a one-time verification ticket; a successful biometric vault unlock can safely reuse this one strong verification.
- Bank-card and ID expiry status is kept in the sanitized list snapshot, so the list can show "expired / expiring soon" directly.

### Fixed
- Passkey counts still showing 0 on the home screen after creation, and entries being edited as login credentials.
- Duplicate-entry scanning possibly merging same-name same-account login credentials and Passkeys into one group.
- Some app Passkey requests failing due to Base64URL padding, native caller origins, or incompatible provider capability declarations.

## 3.6.2 - 2026-07-22

### Added
- Online update check on the About page, preferring the ABI-matching APK and falling back to the universal build.
- Entry detail page shows attachment name, type, size, and integrity info, with a safe export action using a custom download icon.
- Attachment display covers secure notes and all entry types with custom modules, no longer dependent on fixed category fields.

### Improved
- OTP list cards read OTP configuration directly from modular fields, preventing list rebuilds or memory reclamation from leaving only titles.
- Chinese/English UI resources re-converged to in-app switching; notification, recovery key, settings, and detail-page strings stay consistent.
- The Chinese "保险库紧急恢复密钥" naming unified; English uses the FAEVault brand.

### Fixed
- Secure-note edit page having attachments but nothing shown or acted on in the detail page.
- Passkey conflict records still entering credential candidates, reusable request tickets, and conflict details lacking warnings.
- Some background notifications not following the current app language.

## 3.6.1 - 2026-07-18

### Improved
- Bottom navigation Security Center icon uses the Material built-in Security icon instead of a custom PNG, staying visible in dark mode.
- Bottom sheets (AppPicker, ModulePicker) use `surface` color with 0dp shadow to match the theme.
- Home / recycle-bin / sync result card containers unified to `surface`, removing leftover `surfaceVariant` and `background` differences.
- Recycle-bin selected entries gain a `primaryContainer` translucent background feedback.
- `VaultDialog` gains an optional `containerColor` parameter for custom dialog backgrounds.
- Sends a status notification when LAN sync completes.
- LAN key exchange flow now ends by automatically showing a sync result card with local entry count, post-merge entry count, transferred bytes, and other stats.
- LAN sync result card completes local entry count, post-merge count, upload status, and verification status.

## 3.5.0 - 2026-07-14

### Added
- WebDAV gains OAuth 2.0 access tokens, Cookie / Session, and PKCS#12 client-certificate (mTLS) authentication; Android explicitly rejects NTLM/Kerberos when there is no generic domain credential interface, no longer producing fake connections.
- Every editable category can add a standalone attachment module with SAF multi-file import, deletion, SHA-256 integrity checks, and export; attachments are encrypted with the vault and sync across devices.
- Entering the sync page now automatically read-only checks the cloud drive and WebDAV, showing both sides' entries, recycle bins, pending merges, pending uploads, conflicts, remote-missing items, and check time.

### Security
- Tokens, cookies, mTLS, and domain authentication enforce HTTPS; single attachments limited to 16 MB, single modules 64 MB, up to 20 files; empty files, duplicate content, and malformed PKCS#12 files are rejected.
- The Android auth dropdown no longer shows NTLM and Kerberos, which the platform cannot reliably support; old configs fall back to Basic, while the backend keeps rejection checks.

### Improved
- Sync result cards add pre/post entry counts, remote size, deletion propagation, duplicate merging, upload and readback verification status; identical logical content skips meaningless remote rewrites.
- Attachment modules get two-tone icons consistent with the module visual system, using stacked documents and a paperclip to distinguish them from plain image modules.
- Settings expanded cards drop the black square ripple in favor of rounded low-alpha theme-color press feedback, and widen the title tap target.

## 3.4.4 - 2026-07-14

### Added
- A result card after cloud sync completes, clearly showing added, taken-from-remote, kept-local, keep-both, conflict, no-change, and cleaned counts.

### Improved
- Unlock flow split into background preparation plus post-animation commit: decryption, expired-entry cleanup, and list index building run in the background, and the ring/check animation is no longer interrupted by home-screen initialization and password checks.
- Startup account-file scanning and expired-account cleanup move off the UI thread; password checks and vault save are deferred until after the home screen's first frame.
- NAS, Nextcloud, ownCloud, and other compatible services' connection entries use the accurate "WebDAV" name.
- Cloud-drive state uses a decrypted deterministic logic fingerprint, ignoring file time, file size, re-encryption nonce, entry order, and JSON field order changes.

### Fixed
- Cloud document providers with lagging mtimes, metadata-only updates, or re-encrypted identical content wrongly reporting "remote changed".
- Post-decryption list index building and background tasks causing ring stalls or premature success-animation interruption.

---

## 3.4.3 - 2026-07-14

### Added
- Upload the encrypted vault to a user-chosen cloud drive through the Android system file picker.
- Cloud sync gains direct NAS and custom WebDAV connections, validating server and auth before connecting and decrypting verification after upload.
- WebDAV credentials stored encrypted with Android Keystore, with manual disconnect and local-credential clearing.
- Password check cards add risk, duplicate, and low-security password statistics with drill-down to the entries.
- Vault maintenance adds duplicate-entry comparison confirmation instead of merging directly.
- New secure note, server, and custom categories.
- Free-combining, reorderable modules with per-module sensitive flags.
- System Passkey Credential Provider on Android 14 and later, supporting Passkey creation and verification.
- First-launch batched runtime permission requests for camera, images, and Wi-Fi reading by system version.
- Autofill extended to browser web pages with linked-app matching still supported.
- New standalone "Sync" tab in the bottom navigation for LAN sync, backups, and import/export.
- Permanent deletion logs so permanent deletes propagate across devices.

### Improved
- Internal namespace migrated from `com.passmanager` to `com.vault`; the public app ID stays `app.fae.vault`, keeping existing installs and data directories.
- Web autofill adds source metadata parsing, target package identity validation, and login-form save-candidate extraction, reducing browser multi-field and wrong-source mis-fill risk.
- NAS / custom cloud linking changed to a WebDAV folder address, generating `vault_username.pmv` per current account; old full-file addresses auto-convert to parent-directory display. Relink and unlink continue to force master-password verification; unlink still requires a second confirmation.
- Bank-card and ID images keep entry-style preview with per-image deletion; gallery imports immediately auto-OCR and only fill unfilled fields.
- Card and ID modules in custom content add cross-device `images` image entries; camera or gallery imports auto-OCR with zoom preview, per-image deletion, duplicate filtering, and an 8-image cap.
- Enabling cloud sync requires master-password verification and acknowledging the risks; relinking requires master password; unlinking requires master password plus second confirmation, and unlink does not delete the remote vault file.
- Drive and NAS unified to "sync, upload overwrite, relink, unlink"; default sync performs pull, LWW merge, concurrency checks, upload, and readback verification.
- When linking existing cloud data you can choose sync-merge or forced overwrite; if the new-link verification or operation fails, the original link is preserved and the remote file is not silently overwritten.
- Drive linking defaults to choosing a directory and finding `vault_current_username.pmv`; the app refuses auto-creation when the directory already contains another vault, keeping a compatibility entry for directly selecting an existing file.
- Cloud directory linking adds file deletion, same-name replacement, multiple same-name files, and remote metadata-change detection; abnormal states block auto-rebuild/overwrite and prompt relink.
- OTP module adds camera scan and local image recognition; card and ID modules add camera/gallery OCR; address modules can read the current location on demand.
- Module types, algorithms, digit counts, periods, Wi-Fi encryption methods, database types, and ID types become dropdowns; linked apps support direct installed-app selection; images support preview and per-image deletion.
- Wi-Fi module adds camera scanning and local image-recognition import; multi-QR images can be chosen by SSID; open-network imports clear old passwords.
- Modules invoking the camera or system file picker pause auto-lock judgment and resume on return or cancel; current-location actions get immediate feedback.
- Unsaved drafts for new and edited entries persist across lock and resume editing on unlock; save, cancel, vault switching, or entering another editor clears old drafts.
- All password fields and ordinary fields marked sensitive support hide/show, plus edge handling for image counts, duplicate images, scan parameters, and permission denials.
- Custom-module long-press reordering reads live indices with a two-way-consistent 48dp swap threshold, fixing move-up-only and large-card drag sluggishness.
- Home page adds a Passkey virtual category centrally showing Passkeys created by the system Credential Provider, while keeping the login-plus-module sync format.
- Detail title card background now matches the new category icon main color.
- Recycle-bin entry icon circle backgrounds align with the new category icon colors.
- NAS and custom cloud merged into a unified WebDAV connection entry with authentication as a dropdown.
- QR import adds multi-code edge handling: filtered by OTP / Wi-Fi / sync purpose; live scanning only recognizes inside the viewfinder and requires continuous stability; gallery multi-codes can be explicitly selected.
- NAS/custom WebDAV adds ETag or SHA-256 concurrency detection, temp-file atomic replacement, directory creation, retry, HEAD fallback, and a 128 MB safety limit.
- WebDAV supports Basic, Digest, Bearer, and no-authentication modes, plus SHA-256 fingerprint pinning of self-signed HTTPS certificates.
- Cloud configuration isolated per vault; switching accounts does not reuse another account's remote addresses or credentials.
- Secure notes included in sensitive-content second verification scope.
- Removed Google Drive and Microsoft OneDrive official account direct connections, OAuth tokens, and app-specific hidden directories; only system file picker upload remains.
- Cloud-drive upload no longer shows a connecting state; the connection indicator is only for WebDAV, explicitly noting remote sync is managed by the drive app.
- Drive and NAS/WebDAV keep independent link states: not shown when unlinked, red on recent verification failure, green on success.
- Settings groups auto-lock, sensitive-content verification, and clipboard clearing under "Security"; recycle-bin cleanup and password check under "Vault maintenance".
- Unlock wait animation flows continuously into a 12 o'clock-starting ring and check animation.
- Tapping the current bottom-nav item again returns to the top of the page.
- Optimized target-app list continuous scrolling, icon caching, background scanning, and battery use.
- The manual sync address input rises automatically with the keyboard.
- Secondary-page icon backgrounds match category icon main colors.
- Bottom navigation reordered to Home, Recycle Bin, Sync, Settings.
- Login category horizontal tag scrolling auto-scrolls the selected tag into view.
- Home shows total valid entry count while keeping category ordering.
- Detail page shows linked app package names; Passkey key material cannot be hand-edited.
- Returning to the entry list preserves list position; after lock, the app restores the pre-lock page and state.
- Redesigned category and module icons; key icon centering optimized.
- Stats and list refresh immediately after vault maintenance.
- Sensitive-content second verification moved below auto-lock.

### Fixed
- OTP scanning imports only TOTP and HOTP, rejecting invalid OTP types.
- Recycle-bin operations update timestamps so delete, restore, and update participate correctly in LWW merges.
- Strictly merges different-ID entries that are identical except one missing a package name.
- Permanently deleted entries no longer resurrect in later syncs.
- Linked-app package names fully written into vault, backup, and sync data.

---

## 3.2.2 - 2026-07-12

- Added system autofill service and app-package-name association.
- Improved autofill unlock, credential selection, and app matching.
- Added auto-lock settings and restored the lock overlay style.

## 3.1.1 - 2026-07-11

- Added QR-code and manual-address LAN sync.
- Added sponsorship support and a non-GMS scanner fallback.
- Improved list performance, recycle-bin multi-select, and scanner lock behavior.

## 3.0.0 - 2026-07-11

- Updated home, login, search, navigation, and dialog UI.
- Added login tag horizontal scrolling and category quick-add.
- Improved breach check, list indexing, and search performance.

## 2.5.5 - 2026-07-10

- Vault upgraded to segmented-encryption V2 format with legacy-format compatibility.
- Fixed soft-deleted accounts and same-name import conflicts.

---

## [2.4.8] — 2026-06-27

### Changed

- Breach-check data contract aligned with the desktop client per the "Password Breach Check & List Pinning Logic" spec
  - Field renames: `_breach_count` → `leak_pwned_count`, `_leak_checked_at` → `leak_checked_at`, plus new `leak_check_revision`, `leak_common_weak`
  - Cache validity keyed on `leak_check_revision == updatedAt` (§6.1)
  - `isEntryLeaked` prefers the cache and falls back to the local dictionary when missing (§9)
  - `needsOnlineCheck` separated into its own logic (§6.2)
  - Background checks add revision guards and same-password dedupe (§8)
  - List sorting uses `compareBy<Entry> { !isEntryLeaked }.thenBy { titleSortKey }` per §10.1
- Expired/expiring entries no longer auto-pin to the top

### Fixed

- Breach-check scope corrected: only login (password), wifi (wifi_password), api_key (api_key) are checked; api_secret and credit_card/id_card/otp types are excluded

---

## [2.4.6] — 2026-06-27

### Added

- Settings → breach auto-check interval: 0–30 day slider, default re-check every 5 days; 0 = auto-check off
- On-demand checking: scanning triggers only when never checked / interval due / password modified

---

## [2.4.5] — 2026-06-27

### Added

- Bank-card last-4 digits auto-derived from the full card number instead of manual entry; the entry editor gains a `ReadOnlyField` component
- Expired/expiring and breached entries auto-pin to the top (breach first, expiry second), with `#Breached`/`#Expired` virtual filter chips in the category bar
- Multi-format CSV import compatibility: auto delimiter detection (comma/semicolon/tab), Chinese/English column-name aliasing (Bitwarden/1Password and common formats), and type inference from fields when no type column exists
- **Auto breach scan**: after unlock, background detection of all unchecked entries, local dictionary first (millisecond) then online Pwned Passwords (500ms spacing to avoid rate limits); results cached to `_leak_checked_at`/`_breach_count`, confirmed-clean entries are not rescanned
- Pwned Passwords online results persisted to the entry `_breach_count` field on edit; list/detail cards read the breach badge directly instead of editing-time hints only

### Changed

- Breach check extended from LOGIN-only to all entries with password-like fields (API_KEY api_key/api_secret, WIFI wifi_password, CREDIT_CARD cvv/withdrawal_password)

### Fixed

- Non-LOGIN entries with breached passwords not showing the "Breached" badge
- Public breach (Pwned Passwords online) detections showing no hint on cards/detail

---

## [2.4.0] — 2026-06-27

### Added

- Bank-card expiry auto-formatting: turning valid after 4 digits into MM/YY, with blur-time fallback formatting
- Card-number auto-spacing every 4 digits (`VisualTransformation`, display-only; stored value stays numeric)
- Dedicated one-time-code icon: authenticator-style double-plus inside horizontal bars, fully distinct from the login key icon

### Changed

- **VaultListScreen refactored into a paged list**: `HorizontalPager` implements 5 categories (Login / Wi-Fi / Bank Card / ID / API Key) swiping left-right, each category keeping its own `LazyListState` without losing scroll position
- The bottom `CategoryNavBar` is always visible, no longer scrolling away
- The right A-Z-# alphabet index bar shows/hides with scroll state (`AnimatedVisibility`)
- The tag filter bar (login category only) stays permanent, removing scroll-hide animation for visual stability
- Add-menu (FAB dropdown) and tag-rename menu position dynamically with button width, no longer overlapping
- `NavigationBarItem` replaced by a custom `Box + Icon + Text`; selected state uses a color block + rounded background; minimum 64dp height for gesture-navigation bars
- "API Key" tab unified to "密钥" (API Key)
- Recycle-bin title changed from "回收站 (n)" to "回收站-n"
- Add-FAB menu category order follows user ordering, consistent with the bottom navigation bar
- Settings OTP icon updated to the new icon
- Release builds enable R8 minification (`isMinifyEnabled = true`)

### Fixed

- Sidebar index landing offset in paged mode due to `leakedCount` shift: `AlphabetSidebar` accepts `leakedCount` and skips the breached segment in index mapping
- Auto-lock (idle timeout / background) followed by unlock now auto-launches biometrics without tapping the "biometric unlock" button

---

## [2.3.3] — 2026-06-23

### Changed

- Account deletion is now soft-delete: marked with `deletedAt` into an implicit recycle bin, permanently purged 30 days later by `VaultRegistry.purgeExpired` on the next launch; users can trigger the restore dialog by "create account" with the same name on the login page, keeping the fingerprint binding valid — a safe grace period
- `VaultRegistry.list()` / `current()` filter marked accounts; `markForDeletion` only writes to the registry SharedPreferences; physical `.pmv`/`.bak`/`.recovery`/Keystore aliases survive until true expiry
- `VaultViewModel` adds `restoreVault` / `purgeVaultNow` / `isTrashed` and `trashedVaults` StateFlow; startup calls `purgeExpired()` to clear expired records
- The recycle bin is hidden from Settings (avoiding accidental misuse); `WelcomeScreen` / `UnlockScreen` hits the same-name recycle-bin entry after "create account" submit and pops "restore account" for the user to restore or rename

### Fixed

- Wi-Fi QR scan showing immediate "scan failed" after granting authorization: root cause is GMS Code Scanner being an on-demand dynamic module; the first `startScan` call fails before the module is ready, indistinguishable from a genuine scan failure
- Fix: `WifiQr.areModulesAvailable` probes module installation first, toasts "first use, downloading scan dependency, please wait…" then runs `ensureScannerModuleInstalled` before opening the camera
- Returning during scanning no longer pops "scan failed"/"scan cancelled"; unified silent; only real scan errors prompt

## [2.3.2] — 2026-06-23

### Fixed

- Digit-starting entries (e.g. "123微博") taking pinyin initials after ICU transliteration, breaking the Y/Z sidebar segments: `Pinyin.firstLetter` now checks whether the first character is a digit and returns `'#'` directly
- Breached entries pinned to the `visible` list head shifting later tags: `AlphabetSidebar` receives `leakedCount` and skips the breached segment in `firstIndexFor`

## [2.3.1] — 2026-06-22

### Fixed

- Sidebar alphabet index dragging into the lower half lands Y/Z wrong: `Arrangement.SpaceEvenly` inserts extra gaps at top/bottom, laying out 27 letters into 28 equal parts, which mismatches the 27-equal-part slope of `letterAt(y) = (y / (heightPx/27)).toInt()`; the drift grows downward. Each letter now sits in its own `Box(Modifier.weight(1f))` splitting height evenly, each slot exactly `heightPx/27`, with touch mapping strictly aligned to visual position

---

## [2.3.0] — 2026-06-22

### Added — Self-written document scan camera (non-GMS devices)

- New CameraX-based `CameraScanActivity` replacing the old system-camera fallback path
- Live viewfinder: CameraX `ImageAnalysis` samples the YUV Y channel through self-written edge detection, drawing a yellow rectangle outline over the preview letterbox, hugging the document edges across 5–10 frames
- Review / manual crop: after the shot, a review screen shows an initial crop box = the ROI detected in the last viewfinder frame (normalized by `rotationDegrees` to display orientation); users can scale any of 4 corners independently or drag to pan; minimum 6% size; the cropped JPEG is generated and returned only on confirm

### Added — Pinyin sorting and indexing for Chinese

- `Entry.titleSortKey` cached property uses ICU `Han-Latin; Latin-ASCII; Lower` transliteration: 「苹果」→ "ping guo", sorting together with 「Apple」 under a unified Latin comparison
- Main list `VaultOps.sortedByTitle` uses `titleSortKey`; sidebar alphabet index `initialOf` groups by pinyin initial (苹果 → P, 百度 → B), no longer cramming everything into `'#'`
- The transliterator is a single app-wide singleton (ICU `Transliterator` is read-only and thread-safe)

### Changed — Document edge detection algorithm rewrite

- Adaptive threshold switches from "max·25%" to "median of the projected 5–95% interior × 1.8 + absolute floor 800": a single hot spot no longer blows out the threshold and misses weak edges
- Sobel split into per-axis projection: `|Gx|` accumulated per column only for left/right edges, `|Gy|` accumulated per row only for top/bottom edges — card interiors are mostly horizontal text strokes (contributing to mid-`|Gy|`) and no longer misdetected as edges by the left/right pass
- Edge finding changes from "first above-threshold pixel scanning inward" to "argmax in the outer 45% region + threshold check": occasional interior texture above threshold is no longer treated as a card edge
- Added 3×3 mean filtering + 1D projection smoothing (radius 3) to suppress single-pixel noise

### Changed — Static QR decoding without ML Kit

- `WifiQr.scanFromUri` uses local ZXing decoding (`MultiFormatReader + HybridBinarizer` + a second try with inversion + >1600px auto sub-sampling against OOM)
- Removed the `com.google.mlkit:barcode-scanning:17.3.0` dependency; the GMS live-scan UI still comes from `play-services-code-scanner`, and `Barcode.FORMAT_QR_CODE` is provided by its transitive `barcode-scanning-common`

### Fixed

- **Non-Google camera photo-confirm crash**: all downstream exceptions in the `takePictureLauncher` callback (image reading / EXIF decode / OCR errors) are caught by try/catch and toasted; `ocrBusy` resets on user cancel, camera error, and processing failure paths, preventing a permanently spinning button
- **Manual crop 4-corner drag "won't obey"**: `pointerInput` coroutines outlive recomposition and the original closure captured static copies of `cropRect / dispW / dispH / ox / oy` from first composition; now wrapped in `rememberUpdatedState` so gesture callbacks read the latest values and hit-testing/increments track the real frames

### Changed

- Settings → Appearance dropdown width uses `onSizeChanged` to measure the button's real width → `DropdownMenu` with `Modifier.width(buttonWidthDp)`, equal to the trigger button; the old `fillMaxWidth(0.9f)` was too narrow on some screens

---

## [2.2.2] — 2026-06-15

### Fixed

- Fingerprint/biometric-template change leaves the "fingerprint unlock" button silently unresponsive: catches `KeyPermanentlyInvalidatedException`, auto-clears the invalid key, hides the button, tells the user to use the master password, and guides re-binding in settings
- Enabling fingerprint in settings also lacked an onFailure fallback; now reports per-case as BiometricCancelled / BiometricKeyInvalidated / other

### Changed

- Settings → Appearance switches from three side-by-side buttons to a dropdown (visually aligned with "master password recovery" and similar items)

---

## [2.2.1] — 2026-06-15

### Added — Cross-account vault merge guard

- `.pmbak` encrypted backup format upgraded to v2, carrying `syncMeta.deviceId` (vault lineage identifier) and `exportEpoch`, letting the importing side judge "is this the same vault"
- Backup import auto-compares lineage:
  - **Same account vault** → silent LWW merge (as before)
  - **Different account vault / old backup missing lineage info** → "cross-account merge warning" dialog, requiring explicit confirmation; cancel keeps local data untouched
- `BackupCodec.importFrom` returns `BackupPayload` (with syncMeta and exportEpoch) instead of just `List<Entry>`
- `spec/SYNC_V2.md §7.5`: lineage guard spec; the desktop side must implement the same logic to avoid cross-account mis-merges

### Tests

- `SyncV2IntegrationTest` adds 3 cases: BackupPayload with syncMeta round-trip, v1 legacy-backup deserialization compatibility, and lineage-distinction logic

---

## [2.2.0] — 2026-06-15

### Added (Sync v2 — multi-device bidirectional sync groundwork)

- Vault schema upgrade: `VaultPayload` adds `syncMeta.deviceId` (UUID assigned at first vault creation) and `exportEpoch` (local clock refreshed on every write)
- Encrypted `.pmbak` import switches to **LWW (Last-Writer-Wins) merge**: matched by `id`, compared by `updatedAt`; same-second concurrency auto-keeps both, no more user OVERWRITE / SKIP choice
- Deletion uses **tombstones**: `Entry.deletedAt` marks deletion time; tombstone entries propagate with sync so "deleted on A" reaches B and deletes automatically
- "Resurrection" semantics: if B edits an entry after A deleted it, the merge restores B's version
- Clock drift calibration: the merging side computes skew as `localNow - exportEpoch`, translating remote timestamps to the local baseline
- Design/interop spec in `spec/SYNC_V2.md`; cross-device test vectors in `spec/sync_v2_fixtures.json`

### Changed

- Deletion no longer "moves to a recycle-bin table"; it stamps `deletedAt` tombstones in the main list, auto-filtered by UI / search / sort
- `VaultListScreen` main list, entry counts, and tag sources now look only at active entries
- The `VaultListScreen` top-bar recycle-bin badge counts `entries` with `deletedAt != null`
- Plaintext CSV export excludes tombstone entries
- Settings `ImportPolicyDialog` no longer used for `.pmbak` import (LWW needs no policy), still kept for the CSV path

### Migration

- Old v1 vaults auto-migrate at first decode under 2.2.0:
  - Legacy `trash` arrays merge into `entries` (keeping `deletedAt`), clearing `trash`
  - `syncMeta.deviceId` generated
  - The next save persists v2 format

### Tests

- `VaultOpsTombstoneTest` (6): tombstone delete / restore / purge / purgeAll / purgeExpired
- `SyncV2MergeTest` (10): 8 core spec scenarios + clock calibration + combined stats
- `SyncV2IntegrationTest` (2): v1→v2 end-to-end + GC
- `VaultCryptoTest` (6): including new exportEpoch and deviceId migration cases

---

## [2.1.7] — 2026-06-15

### Changed

- Detail-page hidden sensitive fields use a fixed 6 dots, no longer varying with password length (preventing password-length inference)
- New entries return directly to the main page after saving; editing existing entries still stays on the detail page

### Fixed

- "Cancel" and "Keep a copy" buttons visually overlapping on some screens in the conflict dialog

### Added (internal)

- `spec/SYNC_V2.md` + `spec/sync_v2_fixtures.json`: multi-device bidirectional sync spec (entry-level LWW + tombstones + clock calibration) for joint desktop implementation; Android lands it in v2.2.0

---

## [2.1.6] — 2026-06-14

### Changed

- CSV-export risk warning dialog removes the redundant red text "the next step needs to verify your current master password again" — already verified in-session, no need to re-prompt; the wording was misleading

---

## [2.1.5] — 2026-06-14

### Changed

- Settings gate is now "session-scoped": verifying the master password once within a Settings visit covers the session; leaving and re-entering re-verifies
- Irreversible / high-privilege operations still force per-use verification: delete account, change master password

---

## [2.1.4] — 2026-06-14

### Fixed

- UnlockScreen account-switcher's create-account recovery-key dialog also gets destroyed (2.1.3 only fixed the WelcomeScreen path)
- Reused `InitialRecoverySetupDialog` as internal, shared within the package; both create paths run the two-step "account + master password → recovery key" sequence

---

## [2.1.3] — 2026-06-14

### Fixed

- Create-account flow: the recovery-key setup dialog gets destroyed when `createNewVault` triggers navigation, leaving no time to interact
- Changed to a two-step sequence inside the welcome page: step one account name + master password → step two recovery key (save and enter / skip)
- The dialog does not dismiss on outside taps; must choose explicitly; users who skip are covered by the 24h periodic reminder on the main page

---

## [2.1.2] — 2026-06-14

### Added

- Self-built lightweight Markdown rendering: the changelog / privacy-policy dialogs in "About" render headings, lists, tables, bold, inline code, dividers, and link styling instead of plain text

---

## [2.1.1] — 2026-06-13

### Added

- Settings — "Import and merge from CSV": parses the same format as `CsvExporter`, reusing ImportPolicyDialog for conflicts
- Settings — plaintext CSV export risk warning dialog (4 notes) before master-password verification → path selection

---

## [2.1.0] — 2026-06-13

### Added

- App picker becomes a Material 3 ModalBottomSheet: refined list + search + domestic-ROM rejection fallback guidance ("go to settings to enable")
- Online Pwned Passwords k-anonymity query: top 5 SHA-1 chars + Add-Padding, local suffix comparison, full hash never uploaded
- Breached login entries auto-pin to the top for immediate risk visibility
- Settings — clipboard auto-clear duration (0/15/30/60/120/180/300/600 seconds, 0 = never clear)
- Settings — sensitive-content second verification switch; turning off forces master-password verification
- Settings — About card: developer / contact email / privacy policy / changelog

### Changed

- Lock button moves to the top-bar left navigationIcon, physically separated from the right-side recycle bin / settings to avoid mis-taps
- Password field and "generate" button heights unified at 56dp with bottom alignment
- Long titles (account names, cards, detail-page titles) unified with ellipsis
- applicationId changed from `com.passmanager` to `app.fae.vault`

### Fixed

- Domestic-ROM "read app list" consent not refreshing the first time: ON_RESUME re-pull + short-poll on denial

### Removed

- Dead code: old `PermissionUtil.kt`, `os/AppPicker.kt`

---

## [Unreleased] — Pre-launch hardening

### Added

- Startup auto-cleanup of `cacheDir/img_share` / `img_capture` leftovers (decrypted images may remain after a crash)
- Copying sensitive content auto-clears the clipboard after 60 seconds (unless you overwrite it)
- App Bundle build config: language / density / ABI splits; `bundleRelease` directly produces an AAB
- Project root gains `README.md`, `PRIVACY_POLICY.md`, `CHANGELOG.md`

### Changed

- `CardParser` and `WifiQr` add input length limits; malicious OCR / QR input cannot stall parsing
- `VaultRepository` write path adds a `finally` fallback cleanup of `.pmv.tmp`
- ProGuard rules cover `com.passmanager.crypto` / `security` / enum `valueOf` reflection paths

### Removed

- `EntryEditScreen` OCR exception `printStackTrace()` (avoiding stack traces leaking entry fragments to logcat)

### Security

- `FLAG_SECURE` everywhere: screenshots / recordings / system casting globally disabled; recent-task cards show no content
- Clipboard marked `IS_SENSITIVE` on Android 13+

---

## [1.1.0] — 2026-06-13

### Added

- A one-time check animation before switching to the main UI after successful unlock
- Camera / gallery runtime permission requests (system prompt on the first use of each feature)
- "Read installed apps list" user consent dialog (appears on first new-login entry)

### Fixed

- The reminder dialog in AppRoot no longer repeats when enabling "set recovery key" from settings

### Removed

- Dead-code cleanup: `Entry.expiryStatus()` / `expiryDateStr()` etc.
- Legacy path cleanup: `imageKeyLegacy`, `IdleLockPref` minute-key migration, `VaultRegistry` single-vault migration

---

## [1.0.1]

- Added recycle-bin timeout cleanup setting
- Search box debounce removed

## [1.0.0]

- Entry detail-page bottom action bar
- "No tags" chip counts login type only

## [0.1.0]

- Initial release: multi-account vaults, 5 entry types, scrypt + AES-256-GCM encryption, biometrics, Wi-Fi QR, OCR auto-fill