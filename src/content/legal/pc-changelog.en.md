---
title: "PC Changelog"
description: "FAEVault PC changelog"
locale: en
translationKey: pc-changelog
order: 10
---

# PC Changelog

Only records features and fixes for the FAEVault desktop client. Android client changes are maintained in its own repository.

---

## 4.6.7 - 2026-10-07

### Added and improved
- Unified autofill candidate ranking across website origins, linked applications, titles and keywords, with case-insensitive, full-width and related-name matching. Similar candidates do not bypass origin authorization.
- Added custom-field matching, manual field-role selection and encrypted remembered autofill associations. Exclusions and associations travel with vault synchronization.
- Added opt-in remote-update reminders per cloud target, with a silent initial baseline, duplicate suppression and a later option. Checks do not download or overwrite the vault. Android checks while foregrounded and unlocked; PC checks while running and unlocked.
- Moved device information into security settings and removed separate sync/maintenance entries.
- Device names follow the operating system. Android falls back to the model when the system name is unavailable; PC uses the computer name. Views refresh on opening and foreground activation; normal saves and synchronization update remote records.
- Simplified the device page to names, activity and authenticated authorization records, without an application nickname editor.

---

## 4.6.5 - 2026-10-02

### Fixed
- Fixed that secondary verification for sensitive operations could be retried indefinitely. The dialog only shook and showed "incorrect master password" — no counter, no backoff, no cooldown. This gap is worse on desktop than on mobile: the fast path in `verify_password` uses `hmac.compare_digest` without running Argon2id, so a guess costs nearly nothing, whereas the unlock dialog runs the full KDF (64 MiB, t=3) and is throttled by that alone. Secondary verification now shares the same failure record as the unlock page, matching Android's `MasterPasswordDialog` behaviour item for item.
- Fixed that the app still stayed unlocked after secondary verification hit the limit. Consecutive wrong guesses against an already-unlocked vault mean the holder is probably not the owner, so the session should drop to locked immediately.
- Fixed that the cooldown countdown was unreliable. Remaining seconds were counted down in memory, which drifts from the real deadline: after minimising the window, suspending the system or sleeping, the two disagree, and background pausing can end the cooldown early. The countdown is now recomputed from the persisted deadline, with the same 200 ms polling interval as Android.
- Fixed that failure backoff gave no visible feedback. Remaining seconds are now shown during backoff too.
- Fixed that a stale window could clear a cooldown just created by another entry point. UI code should not write security state; it now decides which controls to restore based on the current account.
- Fixed a read-modify-write race in `record_password_failure`. Concurrent failures from the main process and the resident browser_host process could both read the old value, so the cooldown round advanced once instead of twice — looser than intended.
- Fixed that passkey entries could not use tags. Tags are pure metadata but were excluded in four places: loading, import, the tag index and the context menu. The entries themselves stay non-editable (key material is written only by the Credential Provider), but users need to filter and organise them.
- Fixed that the entry editor's deferred resize could fire after the dialog was destroyed. Closing the editor before the event loop dispatched that callback made PySide raise "internal C++ object already deleted".
- Fixed that auto-update only showed download progress, leaving installation completely invisible. The installer's exit code was discarded, so the app could not know whether installation succeeded and failures were entirely invisible to the user. It now shows four stages — download, verify, install, done — and only exits once the installer confirms success.
- Fixed leftover Chinese in the English interface. Automatic sync status is persisted Chinese shown without translation, and the local backup label "Backup device (VOL-xxxx)" only translated the prefix, leaving the volume name and parentheses raw.
- Fixed CSV import dropping tags: the check was mistakenly written to keep only login entries, discarding tags for Wi-Fi, cards, API keys and every other type.

### Changed
- Cloud uploads now stream to the final URL in one pass, closing the window between the two-stage write. Content-level CAS is added for weak-ETag servers: because the merge flow rewrites the snapshot path in place, the SHA-256 recorded at download time is kept separately as the "remote copy" witness. An explicit user "overwrite upload" skips every gate and publishes unconditionally.

---

## 4.6.4 - 2026-09-30

### Fixed
- Fixed "Close page" doing nothing on the host side. That path needs a workspace reference to fall back to the station entry, but the connecting page was never registered with the workspace, so the lookup raised `AttributeError` and Qt swallowed it silently.
- Fixed the connecting device being completely blind to "the other device closed the transfer connection". Errors while polling for transfer items were swallowed, so after the station shut down the connection still looked alive: the sender stayed on the page and the button still read "Disconnect". It now treats repeated failures as a disconnect and converges on one teardown path.
- Fixed the sender area merely being disabled after a disconnect, still occupying the page and looking usable while no longer being able to send. Host side (ended locally / ended by peer / connection timeout) and connecting side (peer closed / connection failed) now actually collapse the sender, switch the button to "Close page", and keep the transfer records for review.
- Fixed connection timeouts not running the disconnect teardown, leaving the sender and button in the wrong state.
- Fixed the sync result never appearing for the connecting side. The result card was additionally gated on "no other channel is busy", and there is a recomposition window between the sync-finished flag clearing and the result being written where neither condition holds, so the result always fell through to the "closed" branch.
- Fixed three Chinese strings that had picked up a stray space (station description, export authorisation hint, export confirmation dialog). Those strings are also the lookup keys for the English translation table, so the extra space made the lookup miss and Chinese leaked into the English UI.
- Removed imports in `ui/sync_pages.py` that no longer had references, and aligned the file's formatting.

### Changed
- Disconnecting now asks for confirmation first. Interrupting a sync abandons the in-flight merge and upload and can leave a half-merged state, which costs more than interrupting a transfer (a transfer only drops individual items). Station shutdown, connector disconnect, and both transfer-page exits now confirm first, matching the Android client.
- The exit after a session ends is uniformly called "Close page" on both the sync and transfer pages. After a disconnect there is nothing left to disconnect, so the button that stays really means "close this page".

---

## 4.6.3 - 2026-09-29

### Fixed
- Fixed "Check for updates" doing nothing. The update dialog's `__init__` had lost its indentation and ended up at module level, so `UpdateDialog` inherited its parent's two-argument constructor while the call site passed three — raising `TypeError`. The exception is raised inside a Qt slot, which PySide6 swallows silently (the windowed build discards stderr too), so the button resets and no dialog ever appears. **The in-app update channel has been dead since 2026-08-20.**
- Fixed "device authorization records cannot be read" breaking key authentication for *every* device on a shared vault. Older Android builds wrote an undefined permission bit into the authorization records and signed them into the vault; the strict 3-bit check here made the whole list unreadable, so no device could authenticate. Records now keep their exact value (signatures and data stay valid) and undefined bits grant nothing. **Existing vaults need no migration or re-entry.**
- Fixed the contradictory LAN state after a peer disconnects: the page kept showing "connected, waiting for sync or transfer…" while the "establish transfer station" button was clickable again. The teardown refreshed the status before stopping the server, but pairing records are only cleared by `stop()`, so the "connected" text was written and then frozen once polling stopped. The teardown now stops the server first, resets the state, and only then reveals the entry — restoring the auto-collapsed QR/pairing hints as well.
- Fixed the LAN gear slider being permanently disabled after a file transfer: the transfer-in-progress flag was only cleared in `__init__`, never on `stop()`, so "a task is running" stayed true forever. `stop()` now also resets the transfer and sync progress.
- Fixed the module card's delete × turning into a solid pink block with the × missing after a click. Painting the hover tint set the painter's pen to *no pen*, and the × then inherited that pen; changing its colour and width does not restore the line style, so both diagonal lines drew nothing. The × now uses its own freshly constructed solid pen, so the tint and the cross coexist.
- Floating buttons are now plainly **translucent**. The frosted-glass treatment was invisible over an entry list: the backdrop is flat, evenly coloured rows, so a Gaussian blur either smeared the rows into the same colour as the background or, at a smaller radius, was crushed below visibility by the glass colour on top (measured contrast as low as 8–20 out of 255) — it just looked transparent. It also re-rendered the entire scroll viewport and blurred it on every paint, triggered by the scrollbar. The blur is gone; the controls are clean translucent surfaces and the per-frame re-render with it.
- Added a cross-end vector for a record carrying undefined permission bits (`permissions=15`), covering decode, signature verification, byte-exact re-encode, and the fact that bit3 grants nothing. Both test runners now iterate every case.

### Changed
- Screen capture protection now defaults to **on** ("allow screen capture" defaults to off): vault contents should not appear in screenshots, screen recordings or screen shares by default. Values the user has explicitly saved (either the new key or the legacy inverse key) are still honoured and are not changed by the new default.

---

## 4.6.2 - 2026-09-26

Republished on 2026-09-27: the x64 installer includes the signed Windows Passkey Provider. Before first installation, users must verify the `FAE-Vault-CodeSigning.cer` supplied with the same release and explicitly add it to Windows `TrustedPeople`; the installer does not silently add trust. The public certificate and installer are covered by `SHA256SUMS.txt`. The portable package does not install the system-level Provider.

### Changes
- The dark theme accent color changed from purple (hue 238°) to a blue from the same family as the light theme (hue 217–222°): `accent` / `accent_hover` / `accent_soft` / `accent_text` / `accent_text_hover` and the primary button are recolored as a whole; the dark primary button stays a solid color (only the light theme uses a deep-blue gradient), matching the original structure.
- LAN is no longer a three-level dropdown menu: it is consolidated into a single entry, and opening it shows a three-stop capsule slider at the top of the page (Start transfer station / LAN sync / File transfer). Switching stops only replaces the content below, without changing the page header, and defaults to "LAN sync". The slider is disabled while a sync or transfer is in progress, and automatically switches to the channel the other device is using.
- The bottom notification placeholder bar was removed and replaced by a floating notification bar above the content area: top-centered, capped at 560px, an inverted capsule (dark background with light text in the light theme), fading out after 4 seconds (180ms in, 240ms out), dismissed immediately on click, and no longer occupying bottom layout height.
- The "Cloud sync" group was removed from the settings page: both the enable switch and the cloud association now live on the "Cloud sync" page itself. The never-wired duplicate handling in the main window (`_on_cloud_sync_toggled` / `_refresh_cloud_sync_controls`, whose `_cloud_sync_toggle` / `_cloud_sync_btn` were never assigned anywhere in the repository and referenced old config keys) was also removed. After the master switch was consolidated onto that page, the menu entry became permanent; otherwise turning the feature off would make the page unreachable.
- The hamburger action panel at the bottom of the category bar was removed; import, export, and maintenance were folded into the "More" menu in the top mini bar.
- The top "Sync" dropdown became "More", regrouped into two submenus: "Sync" covers import/export (4 import + 4 export items), local backup, LAN (Start transfer station / LAN sync / File transfer), and cloud sync; "Maintenance" covers duplicate-entry merge and identical-server merge.
- The manual "compact/clean up database" entry was removed and replaced with automatic maintenance aligned with Android: temporary files are reclaimed in the background at startup and on every unlock, expired trash entries are purged, and a compaction runs immediately after purging entries; media is compacted opportunistically against a separate threshold (at least 10 minutes since the last compaction and at least 32 MB of growth) to avoid the bloat of append-only writes.
- Security center, trash, settings, duplicate-entry comparison, identical-server handling, LAN transfer station/connection, local backup, and cloud sync became persistent tabs inside the editor workspace. Clicking an entry always returns to the fixed "Entry details" tab, while other feature tabs and their state are preserved.
- Feature tabs are single-instance, ask for a second confirmation based on run state before closing, and uniformly clean up background tasks and sensitive sessions on close, lock, account switch, or exit.
- Sync, security center, trash, and settings are right-aligned inside the top mini bar; the right-hand detail card's top edge aligns with the search box top on the left.
- The editor workspace tab bar now uses the window background color; the selected tab takes the content background color with a top rounded corner and bold accent text, and no longer draws a bottom divider, blending into the content below. Adjacent tabs are separated only by a short light vertical line in the middle.
- Editor feature page margins are unified to `PAGE_MARGINS` (20px): the settings page's previous 28px horizontal margins and the missing margins on the cloud sync page and identical-server handling page are all aligned, so pages no longer each define their own values.
- The brand blue palette was folded into the light theme and became the default appearance, and the "Brand blue" option was removed from settings (keeping Follow system / Light / Dark). Existing `brand_blue` values in configuration are migrated to `light` on read, so the appearance is unchanged.
- The "Add entry" button at the bottom of the entry list no longer spans the full row or occupies its own row: it became a bottom-centered floating button overlaying the entries, with width adapting to content (`_FloatingAddButton` reuses the bottom-centered logic of the detail page's action bar, still hosted by the list card). It does not introduce a separate color scheme — like "Edit" in the detail action bar, it follows the common `QPushButton` rules, with identical background, border, and hover/press feedback; the `GhostBar` style that existed only for it was removed too.

### Fixes
- When closing the transfer station, if the temporary TLS file is held (Windows antivirus/indexers commonly hold handles), `SyncServer.stop()` raised `PermissionError` and aborted the entire stop flow, skipping the transfer directory cleanup and result finalization. Temporary file deletion is now best-effort with logging.
- After enabling cloud sync, the console was flooded by `RuntimeError: libshiboken: Internal C++ object (PySide6.QtGui.QAction) already deleted`: the controller was attached to the main window and still emitted signals after the page was destroyed, so view callbacks hit deleted controls (such as the QAction in the "More" menu). Subscriptions now uniformly get an "is the view still alive" guard, auto-disconnect on exception, and no longer log repeatedly (following the same approach as `_set_backup_status`).
- The security center lists results by each entry's own type, but the left list filters by the current category, so cross-category clicks (e.g. sitting on Login then clicking a Wi-Fi result) failed silently. Jumping now first releases the filter blocking that entry (search term / tag / category / security filter) before selecting; same-type jumps leave the user's existing filters alone.
- After starting a transfer station there was no "Stop transfer station" entry; once started, the only way out was closing the whole LAN tab. The session now provides this button: it stops the server, releases the auto-lock blocker, collapses the session UI, and re-enables the entry; it asks for confirmation first if a session is running.
- The "Start transfer station" stop of the LAN menu had no clickable entry: after the menu was consolidated into a single "LAN" item, the flow previously triggered directly by a menu item lost its entry point, leaving that stop as an empty panel. That stop now carries its own description and a "Start transfer station" button, the entry becomes available again after a session ends, and the same page can start again.
- When cloud sync entries were blocked by `can_start` they all returned silently, showing as "clicking does nothing" with no way to tell whether the backend was busy or the button was broken; the reason is now stated (loading settings / a task already in progress / background auto-sync in progress / the previous session has not ended).
- When the association was cleared during cloud sync detection, `_pull_and_preview` returned silently and the busy flag stayed true: the UI stuck at "Detecting cloud vault data…" with all action buttons greyed out. It now finalizes and reports that the association is no longer valid.
- Mermaid wrote negative width/height into the SVG (subtracting text measurements), so Chromium printed `<rect> attribute width: A negative value is not valid.` for each one, flooding the console; an attribute clamping guard now zeroes negative `width`/`height` before rendering (a negative-size `<rect>` renders as 0 anyway), so the visual result is unchanged and the log stays clean.
- The "Trash retention days" setting in settings previously had no effect at all: `purge_expired` was defined but had no call site anywhere in the repository, so expired entries were never cleaned up. Expired cleanup now runs on every unlock, and expired deletion logs are reclaimed at the same time to avoid their linear growth.
- Temporary file reclamation was previously only wired to the manual cleanup button, so crash-residual media import staging files (`import-*.tmp` / `bytes-*.tmp`) and transit files were never reclaimed; they are now cleaned up automatically at startup and on unlock, covering the media directory and reclaiming only staging orphans older than 24 hours.
- On the login page, an incorrect master password stretched the dialog (pushing the unlock button down and never restoring it): the message area now reserves a fixed two-line height, so the dialog size is identical for the error, cooldown, and waiting states.
- The login page's unlock waiting animation moved from an independent line under "Forgot password" into the unlock button itself; while waiting, the button shows a spinner and "Unlocking…", no longer taking extra line height.
- The English login page mixed English and Chinese in error messages (such as "Incorrect master password (4 attempts remaining)"): the body is now translated before the dynamic message template is applied.
- During the post-failure backoff the input field and unlock button remained interactive (pressing Enter in the password field triggers `accept()` directly), which could stack a second verification thread; input is now disabled during backoff.
- Fixed `#Primary` / `#Danger` buttons looking identical in disabled and normal states (objectName rules took precedence over `QPushButton:disabled`), making buttons under cooldown or waiting still look clickable.
- After closing the local backup page, the main window still held a destroyed status tab, so the scheduled backup check raised `Internal C++ object already deleted`; it now automatically drops the reference once invalidated.
- Fixed a `TypeError` from passing `None` to `QListWidgetItem.setSizeHint` when the security center opened the entry list by category.
- Fixed the Qt warning `unique connections require a pointer to member function` when the security center's "view in main list" established its unique connection via a lambda.
- Fixed the rounded border line on the top edge of the detail card being covered by the tab bar: the card's inner padding is now the same width as its 1px border (1px), restoring a continuous top edge.
- After switching themes, the top card of the entry detail still used the old theme's background and border and only updated after re-selecting an entry: the card wrote `surface_alt` / `border` directly into its widget-level stylesheet, and widget-level stylesheets are not recomputed on theme change (the global stylesheet only overrides properties it doesn't declare, but here all of them were declared). Those colors are now handed back to the global stylesheet (`QFrame#DetailTitleCard` already had matching rules), and the widget-level stylesheet keeps only the type-accent left border that the global stylesheet cannot express. The expired notice bar and the "Leaked" field labels, which are also widget-level styles, were switched to objectName / property selectors in the same pass.
- The entry list, trash list, and security center results list previously scrolled by row in Qt's default way: with a fixed row height of 96px, each scroll step skipped exactly one row, so the row position before and after scrolling was identical and only the content changed, which looked like "reskinning in place" rather than scrolling. All three lists now scroll per pixel (`ScrollPerPixel`) and can stop at half a row; with a fixed row height and `setUniformItemSizes(True)` the position calculation remains constant-time, and measured paint counts and timings are unchanged (180 repaints for 30 steps in both cases).
