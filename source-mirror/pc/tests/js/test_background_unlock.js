"use strict";

const assert = require("assert");
const fs = require("fs");
const path = require("path");
const vm = require("vm");
const {webcrypto} = require("crypto");

const root = path.resolve(__dirname, "..", "..", "browser_extension");
let runtimeListener;
let nativeListener;
const posted = [];
const nativePort = {
  onMessage: {addListener(listener) { nativeListener = listener; }},
  onDisconnect: {addListener() {}},
  postMessage(message) {
    posted.push(message);
    queueMicrotask(() => nativeListener({
      version: 1,
      requestId: message.requestId,
      ok: true,
      result: {locked: false},
    }));
  },
};
const runtime = {
  lastError: null,
  connectNative() { return nativePort; },
  getURL(value) { return `chrome-extension://extension-id/${value}`; },
  onMessage: {addListener(listener) { runtimeListener = listener; }},
};
const context = {
  URL,
  Promise,
  clearTimeout,
  console,
  crypto: webcrypto,
  queueMicrotask,
  setTimeout,
  chrome: {
    runtime,
    tabs: {
      query(_query, callback) { callback([]); },
      sendMessage() {},
    },
  },
};
context.globalThis = context;
vm.createContext(context);
for (const file of ["protocol.js", "background.js"]) {
  vm.runInContext(fs.readFileSync(path.join(root, file), "utf8"), context, {filename: file});
}

function send(message, sender) {
  return new Promise((resolve) => {
    assert.equal(runtimeListener(message, sender, resolve), true);
  });
}

(async () => {
  const accepted = await send(
    {action: "unlock", masterPassword: "master"},
    {url: "chrome-extension://extension-id/popup.html"},
  );
  assert.equal(accepted.ok, true);
  assert.equal(posted.length, 1);
  assert.equal(posted[0].action, "unlock");
  assert.equal(posted[0].masterPassword, "master");

  const rejected = await send(
    {action: "unlock", masterPassword: "stolen"},
    {url: "https://example.com/login", tab: {id: 1}},
  );
  assert.equal(rejected.ok, false);
  assert.equal(rejected.error.code, "UNAUTHORIZED");
  assert.equal(posted.length, 1);
  console.log("background unlock boundary tests passed");
})().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
