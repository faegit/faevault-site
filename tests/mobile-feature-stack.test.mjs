import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { featureLayer, featureStackStyle, nextFeatureIndex } from "../src/scripts/mobile-feature-stack.mjs";

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

test("keeps every card visible with the historical graduated stack offsets", () => {
    assert.deepEqual(
        Array.from({ length: 5 }, (_, layer) => featureStackStyle(layer, 5)),
        [
            { translateY: 0, scale: 1, opacity: 1, zIndex: 5 },
            { translateY: 18, scale: 0.965, opacity: 0.94, zIndex: 4 },
            { translateY: 36, scale: 0.93, opacity: 0.88, zIndex: 3 },
            { translateY: 54, scale: 0.895, opacity: 0.82, zIndex: 2 },
            { translateY: 72, scale: 0.86, opacity: 0.76, zIndex: 1 },
        ],
    );
});

test("controller preserves the historical exit, direct-card click, and auto-rotation behavior", async () => {
    const source = await readFile(new URL("../src/scripts/mobile-feature-stack.mjs", import.meta.url), "utf8");
    assert.match(source, /max-width: 760px/);
    assert.match(source, /if \(locked\) return/);
    assert.match(source, /classList\.add\("is-exiting"\)/);
    assert.match(source, /current = index/);
    assert.match(source, /setTimeout\(.*4500/s);
    assert.match(source, /equalizeHeights/);
    assert.match(source, /astro:before-swap/);
});
