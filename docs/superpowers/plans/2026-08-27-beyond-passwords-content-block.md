# Beyond Passwords Content Block Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a bilingual “Beyond passwords” homepage section grounded in the Android implementation of images, attachments, and progressively rendered Markdown.

**Architecture:** Create one self-contained Astro component that owns bilingual copy, semantic markup, and responsive styling. Insert it between the existing feature and security sections, and guard its placement and claims with a source-level regression test.

**Tech Stack:** Astro, TypeScript frontmatter, scoped CSS, Node test runner

---

### Task 1: Add the regression test

**Files:**
- Create: `tests/beyond-passwords.test.mjs`
- Test: `src/components/BeyondPasswords.astro`
- Test: `src/components/HomePage.astro`

- [ ] **Step 1: Write the failing test**

Create a Node test that reads both Astro sources and asserts that `HomePage.astro` imports and renders `BeyondPasswords`, that the component contains matching Chinese and English headings, and that the mechanism labels cover background parsing, progressive rendering, and on-demand access without the phrases “无限容量” or “unlimited capacity”.

- [ ] **Step 2: Run the test to verify it fails**

Run: `node --test tests/beyond-passwords.test.mjs`

Expected: FAIL because `src/components/BeyondPasswords.astro` does not exist.

- [ ] **Step 3: Commit the failing test together with the subsequent implementation**

The test and component form one user-visible unit and will be committed after Task 3 passes.

### Task 2: Build the standalone content block

**Files:**
- Create: `src/components/BeyondPasswords.astro`

- [ ] **Step 1: Define the component contract and bilingual copy**

Accept `locale: Locale`, derive `zh`, and define matching Chinese and English copy for the title, body, capability labels, mechanism headings, mechanism descriptions, document outline, code sample, image label, and attachment label.

- [ ] **Step 2: Add semantic workbench markup**

Render a `section` with `id="beyond-passwords"`, a left copy column, three mechanism rows, and a right abstract workbench containing a document outline, Markdown preview, short code block, image tile, and attachment row. Decorative icons use `aria-hidden="true"`; the mock workbench has a localized accessible label.

- [ ] **Step 3: Add scoped responsive styles**

Use the existing blue-gray palette, opaque white surfaces, subtle shadows, and a two-column desktop layout. At `max-width: 760px`, switch to one column, center the heading and capability labels, keep mechanism text readable, and prevent horizontal overflow. Disable optional transitions under `prefers-reduced-motion`.

### Task 3: Integrate and verify

**Files:**
- Modify: `src/components/HomePage.astro`
- Test: `tests/beyond-passwords.test.mjs`

- [ ] **Step 1: Insert the component**

Import `BeyondPasswords` in the frontmatter and render `<BeyondPasswords locale={locale} />` immediately after `#features` and before `#security`.

- [ ] **Step 2: Run focused and full tests**

Run: `node --test tests/beyond-passwords.test.mjs`

Expected: PASS.

Run: `npm run verify`

Expected: Astro diagnostics report zero errors and warnings, all Node tests pass, and 11 pages build.

- [ ] **Step 3: Verify responsive behavior in a real browser**

Check `/zh-cn/` and `/en/` at 320, 390, 760, 1024, and 1440 pixels. Confirm section order, no horizontal overflow originating from the new block, matching bilingual structure, and visible content with reduced motion enabled.

- [ ] **Step 4: Commit and push only scoped files**

Stage `src/components/BeyondPasswords.astro`, `tests/beyond-passwords.test.mjs`, and only the import/render hunks from `src/components/HomePage.astro`, preserving unrelated working-tree changes. Commit as `feat: add beyond-passwords homepage section`, then push `main` after verification.
