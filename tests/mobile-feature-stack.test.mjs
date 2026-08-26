import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
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

test("controller uses the mobile breakpoint and a single transition lock", async () => {
    const source = await readFile(new URL("../src/scripts/mobile-feature-stack.mjs", import.meta.url), "utf8");
    assert.match(source, /max-width: 760px/);
    assert.match(source, /if \(locked\) return/);
    assert.match(source, /astro:before-swap/);
});
