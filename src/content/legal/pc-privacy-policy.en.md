---
title: "PC Privacy Policy"
description: "FAEVault PC privacy policy"
locale: en
translationKey: pc-privacy-policy
order: 10
---

# FAEVault PC Privacy Policy

> **Effective date: 2026-09-27**
>
> This policy applies to the FAEVault desktop client and explains how the app handles vault data on your own machine, and when it communicates with external devices or services.

## Core Principles

- **Local first:** FAEVault data is stored by default in the local app data directory of the current Windows user.
- **No user tracking:** The app integrates no advertising, behavior analytics, telemetry, or automatic crash reporting.
- **Connect on demand:** The app only performs network communication when you actively use synchronization or online breach checking.
- **Sensitive actions are user-initiated:** Import, export, autofill, sync overwrite, and device-capability access are always triggered by you.

## 1. Local Data Handling

FAEVault PC provides no developer-hosted account or cloud vault. The app processes the following content that you enter or import yourself:

- Accounts, passwords, and one-time verification codes;
- Bank cards, identity documents, Wi-Fi, servers, and secure notes;
- Custom modules, associated applications, and Passkey records;
- App settings, encrypted indexes, and the state required for synchronization.

### Camera, Images, and Location

The app accesses the corresponding device capability only when you click the camera, image recognition, or "Use current location" control in a module.

- Camera frames, selected images, and OCR text are used on this machine only, to fill the current entry;
- Location results returned by Windows are used for the current operation only;
- The app does not record continuously, does not keep location traces, and never sends any of this content to the developer.

## 2. Encryption and Sensitive Data Protection

- FAEVault encrypts data with keys derived from the master password; the master password is never written to the vault file in plaintext.
- When Windows Hello is enabled, the app uses Windows-provided authentication and DPAPI to protect local unlock material, and never reads raw biometric data.
- Passkey private keys are treated as mandatory sensitive fields and never enter the search index, logs, notifications, clipboard, or ordinary previews.
- On supported Windows 11 versions, after you enable the system-level FAE Vault Passkey Provider, the PC client can create Passkeys and sign sign-in requests using private keys in the vault at your direction. The vault must be unlocked and any Windows-required user confirmation must be completed. Private keys are not sent to websites or the developer.

### Windows Passkey Provider

- Windows forwards creation and sign-in requests to the Provider you have enabled. The app processes the current website identifier and account information needed for that request, and stores new credentials in the local encrypted vault.
- For sign-in, the native component uses the matching private key only to produce the signature for that request, which Windows returns to the requester. The private key remains within the vault's controlled processing flow. Sync or export that you choose to enable handles encrypted data as described elsewhere in this policy.
- The certificate used to sign the Provider installer is separate from website Passkey private keys. For a self-signed installer, you must check and trust its public certificate yourself; the installer does not silently add system trust.

### Browser Autofill

After browser autofill is enabled, the extension recognizes username and password fields on HTTPS pages and requests matching entries from the local Native Messaging host, based on the current page origin supplied by the browser.

**Matching and filling flow:**

- Before you select an entry, only the entry title, username, and a random entry identifier are returned;
- Only after you select an entry are its username and password returned;
- The extension never returns credentials on HTTP pages or on pages whose origin does not match;
- Saving and update confirmations are completed in the local window.

**Unlocking inside the extension:**

- The master password briefly enters the extension popup and the background process memory, and is sent to the local host through Native Messaging for verification;
- The master password is never written to extension storage, logs, or web content scripts, and is never sent to developer servers;
- The input value is cleared when the popup closes or the request ends;
- You can still use the local unlock window or Windows Hello instead.

**Private network origins:**

- Private and loopback IP origins must be authorized by you on this machine, per full IP and port;
- Authorization records carry a local integrity signature and can be revoked in settings;
- Public, link-local, multicast, and unspecified IPs cannot be authorized.

When you actively choose "Save what I just filled in" on a page, the current username and password are written to the local vault through the Native Messaging channel between the browser and the local host, and are never sent to developer servers.

Unlinking the browser deletes the local host registration for the current Windows user and the extension copy generated by the app. An extension already installed in the browser must still be removed through the browser itself.

### Native Application Autofill

After native application autofill is enabled, the app acts only when you press the global shortcut:

- It reads the process name, window title, and input control properties exposed by UI Automation for the current foreground Windows application;
- It uses this information to match associated login entries and to identify username and password fields;
- It writes the username and password directly into the target controls through Windows UI Automation.

This process does not go through the clipboard, does not submit automatically, and never sends credentials to the developer or to third-party servers. The app does not continuously record window titles, input content, or keystrokes; when the foreground application is not associated, no vault data is offered.

## 3. Network Communication

### LAN Synchronization

The app listens on a local network port only while you actively start the sync service, and exchanges vault data only with devices that hold the current QR code and PIN. The service uses an HTTPS certificate generated temporarily for each sync, and the QR code carries the certificate SHA-256 fingerprint for the mobile client to pin; the PIN is submitted only through a request header and is not written into the actual sync request URL. Sync does not pass through any developer-operated relay server.

### NAS and Custom Cloud Sync

When you actively enable WebDAV cloud sync, the app connects to the NAS or custom server you entered, and sends that server:

- The encrypted vault file;
- The authentication method you chose, such as username and password, access token, session cookie, client certificate, or Windows domain credentials.

Saved authentication configuration is encrypted with DPAPI scoped to the current Windows user. The app never sends these credentials to any service other than the configured server.

WebDAV accepts HTTPS only, and configuration is isolated per vault lineage. With a self-signed certificate, the connection is allowed only when the certificate SHA-256 fingerprint exactly matches the value you entered; the app never unconditionally ignores certificate errors.

### Cloud Drive File Association

When you associate a `.pmv` file from the sync folder of OneDrive, Dropbox, Jianguoyun, or another cloud drive client:

- The app reads and writes that file only through the local Windows file system;
- The app never signs in to a cloud drive account and never obtains cloud drive OAuth tokens;
- Upload, download, version retention, and cross-device distribution are handled by the corresponding cloud drive client and its provider.

The cloud drive association path is stored on this machine per vault lineage. A normal sync first reads the remote file, decrypts and merges it locally, and then writes the encrypted vault back; an upload-overwrite skips merging and therefore requires explicit confirmation before it runs.

### Online Breach Checking

When online checking is enabled, the app contacts the Pwned Passwords service:

- Only the first 5 characters of the password's SHA-1 hash are sent;
- Neither the full password nor the full hash is sent;
- The returned results are compared locally;
- The service provider may still learn your IP address, the request time, and the hash prefix.

You can turn online checking off at any time.

### Sponsorship and Support

The app provides a "Sponsor" entry in settings, which opens the project sponsorship page in your default browser. The app does not collect, process, or transmit any amount, payment credential, or third-party payment account information related to sponsorship.

## 4. Import, Export, and Clipboard

- You can actively export an encrypted backup, the raw vault, or an encrypted archive;
- Once a file is saved outside the vault directory, its access, sharing, cloud backup, and deletion are controlled by you and the target software;
- An encrypted archive contains migratable data files protected with AES-256 using the passphrase you set at export time;
- After copying sensitive content, the app attempts to clear the clipboard according to your settings, but other local programs may still read the clipboard before it is cleared.

## 5. Synchronization and Deletion

- When an entry goes to the trash, its deletion time is retained;
- After permanent deletion, the app keeps the necessary deletion log to prevent an old device from restoring deleted data during later synchronization;
- Deleting the local vault file or uninstalling the app does not automatically delete exported files, synchronized copies on other devices, or copies in third-party cloud drives.

## 6. Third-Party Components

The app uses Python, PySide, OpenCV, RapidOCR, Windows Runtime, WebExtension Native Messaging, system cryptography components, and other dependencies shipped with the app to implement the interface, encryption, autofill, camera, OCR, geolocation, and import features.

Except for online breach checking and synchronization that you initiate, these features all run on this machine.

## 7. Policy Changes

When the policy changes materially, the app updates the effective date and ships the change with the corresponding client release.
