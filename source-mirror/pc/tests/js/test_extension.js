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

const logic = context.VaultContentLogic;
assert.strictEqual(logic.autofillRole({autocomplete: "section-login username"}), "username");
assert.strictEqual(logic.autofillRole({autocomplete: "shipping postal-code", name: "email"}), "postal_code");
assert.strictEqual(logic.autofillRole({labelText: "API Secret"}), "api_secret");
assert.strictEqual(logic.autofillRole({name: "wifiPassword", type: "password"}), "wifi_password");
assert.strictEqual(logic.autofillRole({name: "ＡＰＩＫｅｙ"}), "api_key");
assert.strictEqual(logic.autofillRole({ariaLabelledByText: "Card holder"}), "cardholder");
assert.strictEqual(logic.autofillRole({name: "monkey"}), null);
assert.strictEqual(logic.autofillRole({name: "passwordResetSearch", type: "text"}), null);
assert.strictEqual(logic.autofillRole({type: "password"}), "password");
assert.strictEqual(logic.autofillRole({type: "password", autocomplete: "new-password"}), null);
assert.strictEqual(logic.isOtpField({name: "adoption"}), false);
assert.strictEqual(logic.selectUsernameField([{type: "text", name: "search"}, password], password), null);
assert.strictEqual(logic.autofillRole({autocomplete: "section-a billing username webauthn", labelText: "Email"}), "username");
assert.strictEqual(logic.autofillRole({autocomplete: "given-name", labelText: "API Secret"}), null);
assert.strictEqual(logic.autofillRole({labelText: "Email", visible: false}), null);
assert.strictEqual(logic.autofillRole({labelText: "Email", readOnly: true}), null);
assert.strictEqual(logic.autofillRole({labelText: "Email", disabled: true}), null);
assert.strictEqual(logic.autofillRole({name: "cardNumber"}), "card_number");
assert.deepStrictEqual(JSON.parse(JSON.stringify(logic.selectFillPasswordFields([
  {id: "normal", type: "password"},
  {id: "wifi", type: "password", labelText: "WiFi Password"},
  {id: "api", type: "password", labelText: "API Secret"},
]).map((field) => field.id))), ["normal"]);
console.log("unified field recognition tests passed");
assert.strictEqual(logic.isMappableField({type: "text"}), true);
for (const field of [
  {disabled: true}, {readOnly: true}, {visible: false},
  {autocomplete: "new-password"}, {autocomplete: "section-a given-name"},
  {autocomplete: "username"}, {autocomplete: "section-a current-password"},
]) {
  assert.strictEqual(logic.isMappableField(field), false);
}
assert.strictEqual(logic.resolvedFieldRole({disabled: true}, {field: "password"}, "field"), null);
assert.strictEqual(logic.resolvedFieldRole({readOnly: true}, {field: "password"}, "field"), null);
assert.strictEqual(logic.resolvedFieldRole({autocomplete: "new-password"}, {field: "password"}, "field"), null);
assert.strictEqual(logic.resolvedFieldRole({autocomplete: "given-name"}, {field: "password"}, "field"), null);
assert.strictEqual(logic.resolvedFieldRole({autocomplete: "email"}, {field: "password"}, "field"), "email");
assert.strictEqual(logic.resolvedFieldRole({labelText: "API Secret"}, {field: "password"}, "field"), "api_secret");
assert.strictEqual(logic.resolvedFieldRole({autocomplete: "off"}, {field: "custom_secret"}, "field"), "custom_secret");
assert.strictEqual(logic.resolvedFieldRole({}, {field: "invalid"}, "field"), null);
assert.strictEqual(logic.resolvedFieldRole({}, {}, "toString"), null);
