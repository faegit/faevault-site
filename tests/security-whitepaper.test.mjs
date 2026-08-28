import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const pageUrl = new URL("../src/components/SecurityPage.astro", import.meta.url);

test("documents the current PMVE cryptographic architecture in both languages", async () => {
    const source = await readFile(pageUrl, "utf8");
    for (const phrase of [
        "Argon2id v1.3",
        "64 MiB",
        "128 MiB",
        "HKDF-SHA256",
        "AES-256-GCM",
        "Vault RootKey",
        "保险库根密钥",
        "Ed25519",
        "PMVE",
        "PMVS",
    ]) {
        assert.ok(source.includes(phrase), `missing security fact: ${phrase}`);
    }
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
    for (const phrase of ["不保护", "Does not protect", "root", "离线猜测", "offline guessing"]) {
        assert.ok(source.includes(phrase), `missing boundary: ${phrase}`);
    }
    assert.match(source, /class="wp-toc"/);
    assert.match(source, /@media \(max-width: 760px\)/);
});
