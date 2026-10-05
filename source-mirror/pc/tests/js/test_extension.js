"use strict";

const assert = require("assert");
const fs = require("fs");
const vm = require("vm");
const path = require("path");

const root = path.resolve(__dirname, "..", "..", "browser_extension");
const context = {URL, console};
context.globalThis = context;
vm.createContext(context);
for (const file of ["protocol.js", "content_logic.js"]) {
  vm.runInContext(fs.readFileSync(path.join(root, file), "utf8"), context, {filename: file});
}

assert.strictEqual(context.VaultProtocol.normalizeBrowserOrigin("https://Example.com/login"), "https://example.com");
assert.throws(() => context.VaultProtocol.normalizeBrowserOrigin("http://example.com"));
assert.throws(() => context.VaultProtocol.validateContentMessage({action: "get", credentialId: ""}));
assert.deepStrictEqual(
  JSON.parse(JSON.stringify(context.VaultProtocol.validateContentMessage({action: "authorize"}))),
  {action: "authorize"},
);
assert.deepStrictEqual(
  JSON.parse(JSON.stringify(context.VaultProtocol.validateContentMessage({action: "unlock", masterPassword: "master"}))),
  {action: "unlock", masterPassword: "master"},
);
assert.throws(() => context.VaultProtocol.validateContentMessage({action: "unlock", masterPassword: ""}));

const username = {type: "email", autocomplete: "username", value: "alice"};
const other = {type: "text", name: "search", value: "query"};
const password = {type: "password", autocomplete: "current-password", value: "secret"};
assert.strictEqual(context.VaultContentLogic.selectUsernameField([other, username, password], password), username);
assert.deepStrictEqual(
  JSON.parse(JSON.stringify(context.VaultContentLogic.selectSavePassword([
    {value: "new-secret", autocomplete: "new-password"},
    {value: "new-secret", autocomplete: "new-password"},
  ]))),
  {password: "new-secret", mismatch: false},
);
assert.strictEqual(context.VaultContentLogic.selectSavePassword([
  {value: "one", autocomplete: "new-password"},
  {value: "two", autocomplete: "new-password"},
]).mismatch, true);
assert.deepStrictEqual(
  JSON.parse(JSON.stringify(context.VaultContentLogic.selectFillPasswordFields([
    {id: "current", autocomplete: "current-password"},
    {id: "new", autocomplete: "new-password"},
    {id: "plain", autocomplete: ""},
  ]).map((item) => item.id))),
  ["current", "plain"],
);

console.log("extension logic tests passed");
