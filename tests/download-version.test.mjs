import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const pageUrl = new URL("../src/components/DownloadPage.astro", import.meta.url);

test("fetches releases with a token so the build is not rate limited", async () => {
    const source = await readFile(pageUrl, "utf8");
    // Actions runner IPs are shared and the unauthenticated api.github.com limit is
    // 60 req/hour, so an anonymous build fetch fails often enough to matter.
    assert.ok(source.includes("GITHUB_TOKEN"), "releases fetch should use GITHUB_TOKEN");
    assert.ok(/Authorization\s*[:=]\s*`Bearer/.test(source), "should send a Bearer token");
});

test("never falls back to a hardcoded version", async () => {
    const source = await readFile(pageUrl, "utf8");
    // A pinned constant plus a silent empty-array catch is what left the site
    // advertising 4.6.2 long after 4.6.3 shipped, with nothing logged.
    assert.ok(
        !/const\s+FALLBACK_VERSION\s*=/.test(source),
        "must not declare a hardcoded FALLBACK_VERSION constant",
    );
    assert.ok(
        !/:\s*FALLBACK_VERSION\s*;/.test(source),
        "no branch may fall back to the old constant",
    );
    assert.ok(
        source.includes('getCollection("legal")'),
        "fallback version should come from the synced changelogs",
    );
    assert.ok(source.includes("changelogVersions"), "fallback should read changelog versions");
});

test("reports release lookup failures instead of swallowing them", async () => {
    const source = await readFile(pageUrl, "utf8");
    const warnCount = (source.match(/console\.warn/g) ?? []).length;
    assert.ok(warnCount >= 2, `expected warnings for both failure paths, found ${warnCount}`);
    assert.ok(
        !/catch\s*\{\s*return \[\];\s*\}/.test(source),
        "the catch block must not silently return an empty list",
    );
});
