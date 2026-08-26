# Mobile Feature Card Stack Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Keep the desktop feature grid unchanged while turning all feature cards into a click-to-advance stacked carousel at `≤760px`, with the sync device artwork removed.

**Architecture:** Extract the index/layer calculations and mobile DOM controller into a focused browser module. `HomePage.astro` supplies localized labels and responsive CSS, while the controller owns one active index, listener cleanup, height measurement, keyboard support, and the transition lock.

**Tech Stack:** Astro 7, TypeScript-enabled Astro scripts, browser DOM APIs, CSS media queries, Node.js built-in test runner, Playwright CLI.

---

### Task 1: Add tested stack index calculations

**Files:**
- Create: `src/scripts/mobile-feature-stack.mjs`
- Create: `tests/mobile-feature-stack.test.mjs`

- [ ] **Step 1: Write the failing unit tests**

Create `tests/mobile-feature-stack.test.mjs`:

```js
import assert from "node:assert/strict";
import test from "node:test";
import { featureLayer, nextFeatureIndex } from "../src/scripts/mobile-feature-stack.mjs";

test("maps cards to cyclic layers from the active index", () => {
    assert.deepEqual(
        Array.from({ length: 5 }, (_, index) => featureLayer(index, 3, 5)),
        [2, 3, 4, 0, 1],
    );
});

test("advances exactly one card and wraps", () => {
    assert.equal(nextFeatureIndex(0, 5), 1);
    assert.equal(nextFeatureIndex(4, 5), 0);
});

test("returns a safe index when no cards exist", () => {
    assert.equal(nextFeatureIndex(0, 0), 0);
    assert.equal(featureLayer(0, 0, 0), 0);
});
```

- [ ] **Step 2: Run the focused test and verify it fails**

Run: `node --test tests/mobile-feature-stack.test.mjs`

Expected: FAIL because `src/scripts/mobile-feature-stack.mjs` does not exist.

- [ ] **Step 3: Implement the pure calculations**

Create `src/scripts/mobile-feature-stack.mjs` with:

```js
export function nextFeatureIndex(current, count) {
    return count > 0 ? (current + 1) % count : 0;
}

export function featureLayer(index, current, count) {
    return count > 0 ? (index - current + count) % count : 0;
}
```

- [ ] **Step 4: Run the focused test and verify it passes**

Run: `node --test tests/mobile-feature-stack.test.mjs`

Expected: 3 tests pass.

- [ ] **Step 5: Commit the calculation layer**

```powershell
git add src/scripts/mobile-feature-stack.mjs tests/mobile-feature-stack.test.mjs
git commit -m "test: define mobile feature stack order"
```

### Task 2: Implement the mobile stack controller

**Files:**
- Modify: `src/scripts/mobile-feature-stack.mjs`
- Modify: `tests/mobile-feature-stack.test.mjs`

- [ ] **Step 1: Add tests for controller source guarantees**

Extend `tests/mobile-feature-stack.test.mjs`:

```js
import { readFile } from "node:fs/promises";

test("controller uses the mobile breakpoint and a single transition lock", async () => {
    const source = await readFile(new URL("../src/scripts/mobile-feature-stack.mjs", import.meta.url), "utf8");
    assert.match(source, /max-width: 760px/);
    assert.match(source, /if \(locked\) return/);
    assert.match(source, /astro:before-swap/);
});
```

- [ ] **Step 2: Run the focused test and verify the new test fails**

Run: `node --test tests/mobile-feature-stack.test.mjs`

Expected: the controller source guarantee test fails because the controller is not implemented.

- [ ] **Step 3: Add the controller to the same module**

Append a controller with this public entry point and behavior:

```js
let activeCleanup = null;

export function initMobileFeatureStack(root = document) {
    activeCleanup?.();
    const grid = root.querySelector("[data-feature-stack]");
    if (!grid) return () => {};

    const cards = Array.from(grid.querySelectorAll("[data-feature-card]"));
    const media = window.matchMedia("(max-width: 760px)");
    const controller = new AbortController();
    let current = 0;
    let locked = false;
    let unlockTimer;

    function render() {
        const mobile = media.matches;
        let maxHeight = 0;
        grid.classList.toggle("is-feature-stack", mobile);
        if (mobile) {
            grid.setAttribute("aria-roledescription", grid.dataset.stackRole ?? "carousel");
            grid.setAttribute("aria-label", grid.dataset.stackLabel ?? "");
        } else {
            grid.removeAttribute("aria-roledescription");
            grid.removeAttribute("aria-label");
        }

        cards.forEach((card, index) => {
            const layer = featureLayer(index, current, cards.length);
            if (mobile) {
                card.dataset.featureLayer = String(layer);
                card.tabIndex = layer === 0 ? 0 : -1;
                card.setAttribute("role", layer === 0 ? "button" : "article");
                card.setAttribute("aria-current", layer === 0 ? "true" : "false");
                card.setAttribute("aria-hidden", layer > 2 ? "true" : "false");
            } else {
                delete card.dataset.featureLayer;
                card.removeAttribute("tabindex");
                card.removeAttribute("role");
                card.removeAttribute("aria-current");
                card.removeAttribute("aria-hidden");
            }
            if (mobile) maxHeight = Math.max(maxHeight, card.scrollHeight);
        });

        if (mobile) grid.style.setProperty("--feature-stack-height", `${maxHeight + 40}px`);
        else grid.style.removeProperty("--feature-stack-height");
    }

    function advance(card) {
        if (!media.matches || locked || card.dataset.featureLayer !== "0") return;
        locked = true;
        current = nextFeatureIndex(current, cards.length);
        render();
        cards[current]?.focus({ preventScroll: true });
        clearTimeout(unlockTimer);
        unlockTimer = window.setTimeout(() => { locked = false; }, 280);
    }

    cards.forEach((card) => {
        card.addEventListener("click", () => advance(card), { signal: controller.signal });
        card.addEventListener("keydown", (event) => {
            if (event.key !== "Enter" && event.key !== " ") return;
            event.preventDefault();
            advance(card);
        }, { signal: controller.signal });
    });

    media.addEventListener("change", () => {
        current = 0;
        locked = false;
        render();
    }, { signal: controller.signal });
    window.addEventListener("resize", render, { signal: controller.signal });

    const cleanup = () => {
        clearTimeout(unlockTimer);
        controller.abort();
        activeCleanup = null;
    };
    document.addEventListener("astro:before-swap", cleanup, { once: true, signal: controller.signal });
    activeCleanup = cleanup;
    render();
    return cleanup;
}
```

When implementing, use the localized instruction from `grid.dataset.stackHint` as the active card's `aria-label`, combining it with the card title. Remove empty ARIA attributes on desktop instead of leaving empty strings.

- [ ] **Step 4: Run the focused and complete unit suites**

Run: `node --test tests/mobile-feature-stack.test.mjs`

Expected: 4 tests pass.

Run: `npm test`

Expected: all content and stack tests pass.

- [ ] **Step 5: Commit the controller**

```powershell
git add src/scripts/mobile-feature-stack.mjs tests/mobile-feature-stack.test.mjs
git commit -m "feat: add mobile feature stack controller"
```

### Task 3: Integrate the stack into the homepage

**Files:**
- Modify: `src/components/HomePage.astro:118-195`
- Modify: `src/components/HomePage.astro:385-470`
- Modify: `src/components/HomePage.astro:985-1105`
- Modify: `src/components/HomePage.astro:1870-1920`
- Modify: `src/components/HomePage.astro:1984-2277`

- [ ] **Step 1: Remove the sync artwork data and markup**

Delete `art: "sync"` from both localized first feature objects. Delete the entire `{feature.art === "sync" && (...)}` block containing `.sync-art`, `.sync-node`, and `.sync-line`. Delete all `.sync-art`, `.sync-node`, and `.sync-line` CSS rules.

- [ ] **Step 2: Add stable hooks and localized stack labels**

Add localized copy fields:

```js
featureStackLabel: zh ? "功能亮点轮播" : "Feature highlights carousel",
featureStackHint: zh ? "点击或按回车查看下一项" : "Click or press Enter to view the next item",
```

Apply hooks to the existing elements without changing desktop semantics:

```astro
<div
    class="features-grid"
    data-feature-stack
    data-stack-role={zh ? "轮播" : "carousel"}
    data-stack-label={copy.featureStackLabel}
    data-stack-hint={copy.featureStackHint}
>
    {features.map((feature) => (
        <article class:list={["feature-card", feature.kind]} data-feature-card data-reveal>
```

- [ ] **Step 3: Add mobile-only stack CSS**

Inside the existing `@media (max-width: 760px)` block, replace the simple full-width feature-card rules with:

```css
.features-grid.is-feature-stack {
    position: relative;
    display: block;
    height: var(--feature-stack-height, 340px);
    perspective: 1000px;
}
.is-feature-stack .feature-card {
    position: absolute;
    inset: 0;
    min-height: 300px;
    cursor: default;
    transform-origin: center top;
    transition: transform 280ms cubic-bezier(0.22, 1, 0.36, 1), opacity 220ms ease;
}
.is-feature-stack .feature-card[data-feature-layer="0"] {
    z-index: 5;
    cursor: pointer;
    transform: translateY(0) scale(1);
}
.is-feature-stack .feature-card[data-feature-layer="1"] {
    z-index: 4;
    transform: translateY(16px) scale(0.97);
}
.is-feature-stack .feature-card[data-feature-layer="2"] {
    z-index: 3;
    transform: translateY(32px) scale(0.94);
}
.is-feature-stack .feature-card[data-feature-layer="3"],
.is-feature-stack .feature-card[data-feature-layer="4"] {
    z-index: 1;
    opacity: 0;
    pointer-events: none;
    transform: translateY(42px) scale(0.92);
}
```

Within the existing reduced-motion media query, set `.is-feature-stack .feature-card { transition: none; }`.

- [ ] **Step 4: Initialize the controller with existing page lifecycle code**

At the top of the existing script, import:

```js
import { initMobileFeatureStack } from "../scripts/mobile-feature-stack.mjs";
```

Call `initMobileFeatureStack()` next to `initCarousel()` and `initTilt()` in both the initial execution and `astro:page-load` handler. The module-level cleanup ensures the second call replaces prior listeners rather than stacking them.

- [ ] **Step 5: Run static verification**

Run: `npm run check`

Expected: 0 errors, 0 warnings, 0 hints.

Run: `npm test`

Expected: all tests pass.

Run: `npm run build`

Expected: 13 pages build successfully.

- [ ] **Step 6: Commit the homepage integration**

```powershell
git add src/components/HomePage.astro src/scripts/mobile-feature-stack.mjs tests/mobile-feature-stack.test.mjs
git commit -m "feat: stack feature cards on small screens"
```

### Task 4: Verify interaction and responsive boundaries

**Files:**
- Modify only if verification finds a defect: `src/components/HomePage.astro`, `src/scripts/mobile-feature-stack.mjs`, `tests/mobile-feature-stack.test.mjs`

- [ ] **Step 1: Start the built preview**

Run: `npm run preview -- --host 127.0.0.1 --port 4344`

Expected: preview is available at `http://127.0.0.1:4344/faevault-site/`.

- [ ] **Step 2: Verify mobile behavior with Playwright CLI**

Open both `/zh-cn/` and `/en/` at widths `320`, `390`, and `760`.

For each route, assert:

- `.features-grid` has `is-feature-stack`.
- exactly one card has `data-feature-layer="0"`.
- one click changes the active title to the next feature and never skips two.
- five clicks return to the original feature.
- `Enter` and space each advance one feature.
- `.sync-art` and `.sync-node` do not exist.
- `document.documentElement.scrollWidth <= document.documentElement.clientWidth`.
- browser console has zero errors.

- [ ] **Step 3: Verify desktop remains unchanged**

At widths `768`, `1024`, and `1440`, assert:

- `.features-grid` does not have `is-feature-stack`.
- cards retain grid-column spans `7`, `5`, and `4` through computed layout.
- cards are not exposed as buttons and have no stack layer attributes.
- no horizontal overflow or console errors occur.

- [ ] **Step 4: Verify reduced motion**

Emulate `prefers-reduced-motion: reduce` at `390px`. Click the active card and assert that the active index advances while the computed transition duration is `0s`.

- [ ] **Step 5: Run final verification and inspect the scoped diff**

Run: `npm run verify && npm run test:content && git diff --check`

Expected: all commands pass; only the planned homepage, stack module, and stack test files differ from the implementation base. Preserve the pre-existing deletion of `.astro/collections/guides.schema.json` and the untracked `docs/plans/` directory.

- [ ] **Step 6: Commit any verification fixes**

If no fixes were required, skip this commit. Otherwise:

```powershell
git add src/components/HomePage.astro src/scripts/mobile-feature-stack.mjs tests/mobile-feature-stack.test.mjs
git commit -m "fix: stabilize mobile feature card rotation"
```
