# Security Whitepaper Rewrite Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the current bilingual security card wall with a complete, code-grounded Android security whitepaper and a readable responsive document layout.

**Architecture:** Keep the bilingual copy and rendering model together in `SecurityPage.astro` so section parity is visible during review. Render a shared table of contents, summary, narrative sections, fact tables, and boundary callouts from locale-specific data with identical structure. Protect critical claims with a focused source test and validate both routes through Astro check/build.

**Tech Stack:** Astro 7, TypeScript in Astro frontmatter, scoped CSS, Node.js built-in test runner.

---

## File map

- `src/components/SecurityPage.astro`: owns bilingual whitepaper content, document rendering, anchors, fact tables, callouts, and responsive styles.
- `src/pages/zh-cn/security.astro`: owns Chinese title and search description.
- `src/pages/en/security.astro`: owns English title and search description.
- `tests/security-whitepaper.test.mjs`: protects section parity, current cryptographic facts, corrected biometric wording, honest boundaries, and responsive navigation.

### Task 1: Add security whitepaper content tests

**Files:**
- Create: `tests/security-whitepaper.test.mjs`

- [ ] **Step 1: Write the failing source tests**

Create a Node test that reads `SecurityPage.astro` and asserts the following exact invariants:

```js
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const pageUrl = new URL("../src/components/SecurityPage.astro", import.meta.url);

test("documents the current PMVE cryptographic architecture in both languages", async () => {
    const source = await readFile(pageUrl, "utf8");
    for (const phrase of [
        "Argon2id v1.3", "64 MiB", "128 MiB", "HKDF-SHA256", "AES-256-GCM",
        "Vault RootKey", "保险库根密钥", "Ed25519", "PMVE", "PMVS",
    ]) assert.ok(source.includes(phrase), `missing security fact: ${phrase}`);
});

test("describes biometric RootKey wrapping without claiming plaintext password storage", async () => {
    const source = await readFile(pageUrl, "utf8");
    assert.match(source, /AndroidKeyStore/);
    assert.match(source, /BIOMETRIC_STRONG/);
    assert.match(source, /vault-bound RootKey|与保险库身份绑定的 RootKey/);
    assert.doesNotMatch(source, /envelope holding the master password|信封（其中包含主密码）/);
});

test("states security boundaries and keeps the document responsive", async () => {
    const source = await readFile(pageUrl, "utf8");
    for (const phrase of ["不保护", "Does not protect", "root", "离线猜测", "offline guessing"])
        assert.ok(source.includes(phrase), `missing boundary: ${phrase}`);
    assert.match(source, /class="wp-toc"/);
    assert.match(source, /@media \(max-width: 760px\)/);
});
```

- [ ] **Step 2: Run the focused test and verify it fails**

Run: `node --test tests/security-whitepaper.test.mjs`

Expected: at least one assertion fails because the current page lacks the complete document structure and corrected biometric wording.

- [ ] **Step 3: Commit the failing test**

Run:

```text
git add tests/security-whitepaper.test.mjs
git commit -m "test: define security whitepaper requirements"
```

### Task 2: Rewrite the bilingual security document

**Files:**
- Modify: `src/components/SecurityPage.astro`

- [ ] **Step 1: Replace the locale data model**

Define matching Chinese and English content with these exact top-level section IDs, in this order:

```ts
const sectionIds = [
    "overview",
    "threat-model",
    "cryptography",
    "key-lifecycle",
    "storage",
    "android-protections",
    "autofill-passkeys",
    "sync",
    "backup-export",
    "guidance-limitations",
];
```

Each locale object must provide `kicker`, `title`, `intro`, `snapshot`, `summary`, `tocLabel`, `sections`, and `closing`. Each section must use one of three explicit content forms: narrative paragraphs, fact rows, or boundary callouts. Both languages must cover identical facts and section ordering.

- [ ] **Step 2: Ground all mechanism copy in Android source**

Write the final copy with these confirmed facts:

```text
Argon2id v1.3 standard profile: 64 MiB, 3 iterations, parallelism 1
Argon2id hardened profile: 128 MiB, 4 iterations, parallelism 1
Supported read bounds: 64–256 MiB, 3–10 iterations, parallelism 1–4
Random Vault RootKey: 256 bits
Purpose separation: HKDF-SHA256
Authenticated encryption: AES-256-GCM with random nonce and contextual AAD
Header authentication: HMAC-SHA256
Signing identity: Ed25519
Recovery secret: random 256 bits with Crockford Base32 representation and checksum
Biometric material: vault-bound PMVE RootKey material wrapped by AndroidKeyStore AES-GCM and gated by BIOMETRIC_STRONG
Unlock failures: 250 ms, 500 ms, 1 s, 2 s delays; then 30 s rounds that increase by 30 s
Android backup and device transfer: excluded
```

Do not claim that in-app cooldown prevents offline attacks, that a rooted device is protected, that all exports are encrypted, that remote providers see no metadata, or that the software has passed an independent audit.

- [ ] **Step 3: Replace the card-wall rendering**

Render the summary, sticky-capable table of contents, narrative article sections, technical fact tables, protect/does-not-protect callouts, and closing snapshot note using semantic `nav`, `section`, `article`, `table`, and `aside` elements. Keep every section heading linked through its stable ID.

- [ ] **Step 4: Implement document-focused responsive styles**

Use a two-column desktop shell with a compact navigation column and a readable content column. At `max-width: 960px`, collapse to one column. At `max-width: 760px`, make the table of contents horizontally scrollable, turn fact-table rows into stacked blocks, reduce section spacing, and preserve tap targets. Add a reduced-motion rule and `scroll-margin-top` for anchored headings.

- [ ] **Step 5: Run the focused test**

Run: `node --test tests/security-whitepaper.test.mjs`

Expected: all security whitepaper tests pass.

- [ ] **Step 6: Commit the page rewrite**

Run:

```text
git add src/components/SecurityPage.astro
git commit -m "feat: rewrite security whitepaper from Android source"
```

### Task 3: Align route metadata

**Files:**
- Modify: `src/pages/zh-cn/security.astro`
- Modify: `src/pages/en/security.astro`

- [ ] **Step 1: Update descriptions**

Use these exact descriptions:

```astro
description="基于现阶段安卓实现，说明保险库的威胁模型、PMVE 加密架构、密钥管理、平台防护、同步与安全边界。"
```

```astro
description="A code-grounded explanation of FAEVault's threat model, PMVE cryptography, key management, Android protections, sync, and security boundaries."
```

- [ ] **Step 2: Run Astro type/content checks**

Run: `npm run check`

Expected: zero errors.

- [ ] **Step 3: Commit metadata**

Run:

```text
git add src/pages/zh-cn/security.astro src/pages/en/security.astro
git commit -m "docs: align security page metadata"
```

### Task 4: Verify the completed whitepaper

**Files:**
- Verify only; no expected source changes.

- [ ] **Step 1: Run all tests**

Run: `npm test`

Expected: every Node test passes, including `security-whitepaper.test.mjs`.

- [ ] **Step 2: Run the production build**

Run: `npm run build`

Expected: Astro builds both `/zh-cn/security/` and `/en/security/` without errors.

- [ ] **Step 3: Check formatting and scope**

Run:

```text
git diff --check HEAD~3..HEAD
git status --short
```

Expected: no whitespace errors and no unrelated files in the implementation commits.

- [ ] **Step 4: Review generated pages at desktop and mobile widths**

Open both language routes at approximately 1440 px and 390 px widths. Confirm headings are not clipped, the table of contents remains usable, fact rows do not overflow, Chinese and English sections have matching order, and long English strings wrap normally.

- [ ] **Step 5: Finish the branch**

Use the finishing-a-development-branch workflow to integrate the verified implementation without touching the user's unrelated main-worktree changes.
