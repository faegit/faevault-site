import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const componentUrl = new URL("../src/components/BeyondPasswords.astro", import.meta.url);
const stylesUrl = new URL("../src/styles/beyond-passwords.css", import.meta.url);
const homeUrl = new URL("../src/components/HomePage.astro", import.meta.url);

test("places the beyond-passwords section between features and security", async () => {
    const home = await readFile(homeUrl, "utf8");
    assert.match(home, /import BeyondPasswords from "\.\/BeyondPasswords\.astro"/);
    const features = home.indexOf('id="features"');
    const beyond = home.indexOf("<BeyondPasswords");
    const security = home.indexOf('id="security"');
    assert.ok(features >= 0 && features < beyond && beyond < security);
});

test("keeps bilingual product claims aligned with the Android implementation", async () => {
    const source = await readFile(componentUrl, "utf8");
    for (const phrase of [
        "不止管理密码",
        "Beyond passwords",
        "图片",
        "Images",
        "附件",
        "Attachments",
        "Markdown",
        "后台解析",
        "Background parsing",
        "渐进渲染",
        "Progressive rendering",
        "按需读取",
        "On-demand access",
    ]) {
        assert.ok(source.includes(phrase), `missing bilingual phrase: ${phrase}`);
    }
    assert.doesNotMatch(source, /无限容量|unlimited capacity/i);
});

test("provides a mobile layout and reduced-motion fallback", async () => {
    const source = await readFile(stylesUrl, "utf8");
    assert.match(source, /@media \(max-width: 760px\)/);
    assert.match(source, /@media \(prefers-reduced-motion: reduce\)/);
});
