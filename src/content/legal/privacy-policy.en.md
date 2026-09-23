---
title: "Privacy Policy"
description: "FAEVault Android privacy policy"
locale: en
translationKey: privacy-policy
order: 0
---

# FAEVault Android Privacy Policy

**Effective date: 2026-09-23**
**Applies to: Version 4.5.0 and later**

This privacy policy explains how the FAEVault Android client handles data, uses system permissions, and communicates with external services while running. By using this app, you confirm that you have read and understood the data handling practices described in this policy.

---

## 1. Basic Principles

FAEVault is a local-first password and credential manager. The app does not provide a developer-hosted account system or cloud vault, and does not integrate advertising, user-behavior analytics, telemetry, or automatic crash reporting.

Vault content is stored on your device by default. Except for LAN sync and file transfer, import/export, autofill, Passkey, online breach checking, update checks that you enable yourself, or cloud sync that you configure explicitly (including auto-sync), the app does not proactively send vault data to other devices or services.

## 2. Data We Process

The app may process the following data that you actively enter, import, generate, or choose to transfer:

- Login accounts, passwords, one-time code secrets, bank cards, ID documents, Wi-Fi, servers, secure notes, and custom modules;
- Attachment files, including images, documents, and any other file types you add; attachments are stored encrypted inside the vault and participate in sync;
- Associated app package names, website domains, and tags;
- Passkeys created through the Android Credential Provider, including relying-party information, user handles, credential IDs, public keys, private keys, and signature counters;
- Images, QR codes, CSV files, encrypted backups, and vault files you choose to import;
- Files, images, and text received or sent over LAN transfer;
- Local backups: encrypted vault backup files written to a local directory you choose or to external USB drives / hard disks;
- Recovery keys and emergency recovery information: recovery keys generated during re-issue, their key versions, and creation times;
- Local preferences such as theme, auto-lock duration, clipboard clear time, and cloud sync interval.

The app does not proactively read contacts, SMS, call logs, calendar, or the advertising ID, and does not continuously collect or log location traces. Your location is read once only when you tap "Use current location" in the address module.

## 3. Local Storage and Security Measures

The vault file is stored in the app's private directory and encrypted with a key derived from your master password. Starting with 4.0.0, the app uses the new-generation PMVE encryption container: incremental commits, block-level encryption, object indexing with integrity checks, and automatic compression; attachments and media are stored as encrypted objects. Your master password exists in app memory only during unlock and required verification, and is never written in plaintext into the vault file.

Local backup uses the system document picker to authorize writes to a local directory you choose or to an external USB drive / hard disk. Before writing, the app identifies the target storage's unique identity (such as device serial number, partition ID, volume label, etc.) to prevent accidental overwrites caused by drive-letter changes; backups overwrite the source vault file on the schedule you set and do not execute sync. Backup files remain only in the directory you chose; uninstalling the app will not delete them automatically. Temporary files left by an interrupted import or backup are reclaimed automatically on the next launch.

Passkey private keys are stored as mandatory sensitive fields in the encrypted vault and never enter the search index, notifications, clipboard, logs, or normal previews. Passkey creation and signing are performed only through the Android system Credential Provider flow.

Biometrics are provided by Android BiometricPrompt and Android Keystore. The app does not capture or store raw biometric data such as your fingerprint or face image.

Temporary files from scanning, sharing, and similar features are stored in the app cache directory and cleaned up on subsequent launches. Files, images, and text received through LAN transfer are persisted to the system public Downloads directory (Internal storage/Download/Vaultshare) so you can view and manage them; those files are under the control of you and your file manager, and uninstalling the app will not delete them automatically.

Android Auto Backup is disabled; the app does not upload vault files through Android's automatic backup.

The app blurs entry thumbnails and image previews by default and shows the original only after the required verification; this is independent of the secondary protection for sensitive content, and turning image blur off does not remove the verification requirement for sensitive photos.

The app applies Android's `FLAG_SECURE` by default to prevent the main screen from being captured, recorded, or shown in the recent-apps preview. You can verify your master password in Security Settings and confirm the risks before turning this protection off; once disabled, the system, screen-casting tools, other apps, or bystanders may capture sensitive content shown on screen. Independent sensitive windows such as autofill authentication, Passkey credential operations, and sync QR scanning always keep screenshot protection.

## 4. Permissions and Their Use

Relevant permissions are requested on demand by each feature at first use. Declining a permission does not block basic vault viewing and editing, but the corresponding feature may be unavailable. You can revoke permissions at any time in the system settings.

| Permission or system capability | Purpose |
|---|---|
| Camera | Scanning one-time codes, Wi-Fi QR codes, sync QR codes, and taking photos of documents |
| Images and media | Reading images or attachments you actively choose for recognition, import, or entry attachment modules |
| Notifications | Showing sync completion, LAN transfer progress, and foreground service status prompts |
| Nearby Wi-Fi devices | Reading current Wi-Fi information on Android 13 and later |
| Approximate or precise location | Filling the current location for the address module when you trigger it; on Android 12 and below, also used to read the current Wi-Fi name. You may grant only approximate location; the app does not continuously locate or log location traces |
| Wi-Fi state | Checking the current network and assisting Wi-Fi import |
| Installed app list | Showing selectable apps and package names in the linked-app picker |
| Biometrics | Protecting vault unlock and sensitive operations with system authentication |
| Network access | LAN sync and file transfer, manually connected WebDAV services, cloud sync, update checks, and online breach checks when enabled |
| Foreground service | Showing a persistent running status in the notification bar during auto-sync, LAN transfer, or cloud upload/download |
| Autofill service | Providing credentials you confirm and select to apps or web forms once you enable it |
| Credential Provider | Creating, selecting, and verifying Passkeys on Android 14 and later |

INTERNET, Wi-Fi state, biometric declarations, and reading the app list may not show standard runtime permission dialogs on some systems. The Autofill service and the Credential Provider must be enabled separately by you in the Android system settings.

## 5. Network Communication

### 1. LAN Sync and File Transfer

When you actively scan a sync QR code, enter a server address, or start a transfer station, the app establishes a connection with the specified LAN device to exchange encrypted vault sync data, entry update timestamps, and deletion logs, or to transfer files, images, and text of your choosing. Sync and transfer do not pass through a developer-operated relay server.

LAN communication accepts HTTPS only, and verifies the SHA-256 fingerprint of the temporary certificate carried by the QR code. The PIN is neither a request parameter nor a request header: both sides use it locally as the SPAKE2 password in the key agreement, and only a one-time ticket travels over the network. Note that the sync address and sync QR code themselves embed that PIN, so treat it as sensitive and show it only to trusted devices. You should still only connect to trusted devices and double-check the sync address and PIN. Content received via transfer is saved into the public Downloads directory, as described in Section 3 of this policy.

### 2. Online Breach Checking

When online breach checking is enabled, the app connects to api.pwnedpasswords.com. The app first computes a SHA-1 hash of each password locally and sends only the first 5 characters of the hash, comparing the returned results locally; the full password and full hash are never sent.

Like any internet communication, that service may observe your IP address, request time, User-Agent, and hash prefix. You can turn off online breach checking in settings; when off, only the local weak-password check is performed.

### 3. User-Authorized Cloud File Sync

Cloud features are off by default. Once enabled, you can use the Android system document picker to associate the encrypted vault file with a cloud drive or other document provider of your choosing. The app does not sign in to cloud accounts and does not store cloud account passwords or OAuth tokens.

After association, the app stores the directory URI or file URI returned by the system and requests persistent read/write permission so it can find the corresponding vault file and sync or upload-overwrite when you act. Sync first reads the file, decrypts and merges locally, then writes back the encrypted vault and reads it back for verification; upload-overwrite skips merging and therefore requires your explicit confirmation before execution. When you unlink, the app releases the persistent permission for the corresponding URI and clears the local association record.

Auto-sync is off by default. Once enabled, the app checks and syncs the associated cloud file or WebDAV server in the background through a foreground service at the interval you choose (from 15 minutes to weekly); when the same target fails repeatedly, auto-sync pauses automatically and shows a hint in the UI. Auto-sync runs only after you enable it and can be turned off at any time in settings.

Specific cloud services or WebDAV servers may process account information, IP addresses, request times, and encrypted files; their handling is governed by the respective service provider or server administrator.

You can also connect directly to NAS, Nextcloud, ownCloud, or other custom servers over WebDAV. When connecting, the app sends the selected authentication information to the address you provide, including username and password, access tokens, session cookies, or client certificates; vault files uploaded and downloaded remain encrypted. Server addresses and authentication configuration are stored encrypted with keys protected by Android Keystore. The app never sends these credentials to any service other than the configured server.

WebDAV configurations are isolated per vault. The release Android app forbids cleartext network communication; with self-signed HTTPS certificates, the app connects only when the certificate's SHA-256 fingerprint exactly matches the value you entered; the app does not offer an option to ignore all certificate errors.

### 4. Update Checks

When you tap "Check for updates" on the About page, the app queries the project release repository (GitHub Releases API) for the latest version and, after selecting the APK matching the device ABI, downloads it directly inside the app. After the download completes, the app verifies that the installer's signature matches the current version before upgrading through the system installer; on Android 8.0+ the first install requires allowing "Install unknown apps" in system settings. Such requests may include your IP address, request time, and User-Agent; they do not include vault data. Update checks are triggered by you.

## 6. Autofill and Passkey

Once autofill is enabled, the Android system calls this app when apps or browsers request credentials. Only after you unlock the vault and select a credential are the relevant fields provided to the target app or web page through the Android Autofill Framework.

Once the Credential Provider is enabled, the Android system hands Passkey creation or verification requests to this app. The app validates the relying-party domain and the caller, then generates or uses the corresponding key after user authentication. The relying-party website receives the public key credential response required by the WebAuthn protocol and never receives the Passkey private key.

## 7. Import, Export, Clipboard, and Sync Responsibilities

You can export encrypted backups, raw vaults, or plaintext CSV voluntarily. Once files are saved outside the app's private directory, their storage, sharing, cloud backup, and deletion are controlled by you and the destination app. Plaintext CSV files do not have the vault's encryption protection.

When you copy sensitive content, the app asks the system to mark the clipboard content as sensitive and tries to clear it after the configured time. Other apps, input methods, or system components may still access the content while the clipboard is valid.

Cross-device sync copies the vault data and encrypted Passkey records you choose to sync to another device. The PC client only manages and syncs Passkey data and never performs Passkey signing.

## 8. Third-Party Components

This app uses AndroidX, Kotlin, Bouncy Castle, ZXing, CameraX, OpenCV, Google ML Kit (on-device text recognition only), OkHttp, and commonmark for the UI, encryption, QR scanning, OCR, network requests, and document rendering. QR scanning and document edge detection run entirely on-device and use neither Google Play Services scanner UI nor network access. These components are subject to their respective licenses and the policies of device system services.

OCR, QR parsing, and vault encryption/decryption run locally on the device. The external communications of online breach checking and update checks are described in Section 5 of this policy.

## 9. Data Retention and Deletion

When you delete an entry in the app, it moves to the recycle bin with a deletion timestamp so it can be restored and so deletion state can propagate across devices. After the auto-purge period is reached or a permanent delete is performed, the app removes the entry content while retaining the necessary deletion log to prevent stale devices from resurrecting deleted data during sync.

Clearing app data or uninstalling the app deletes the local vault and settings in the app's private directory. Data that has been exported elsewhere, synced to other devices, saved to the public Downloads directory or a local backup directory, or saved by another app will not be deleted automatically when you uninstall.

## 10. Minors

This app is not aimed at minors, does not build user profiles, and does not show age-based content or advertising. Guardians should decide based on device usage whether minors may store sensitive credentials.

## 11. Policy Changes

When this privacy policy changes materially, the effective date of this document will be updated and published together with an app version. The new policy takes effect when the corresponding version is installed or updated.