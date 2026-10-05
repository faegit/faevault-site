"use strict";

import assert from "node:assert/strict";
import {spawn} from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import {fileURLToPath} from "node:url";

const extensionId = "mkgodfefjfbgipnanaimcaopapmccaeb";
const edge = process.env.EDGE_PATH || "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe";
// Exercise the checkout by default; installed copies may belong to an older release.
const extension = process.env.VAULT_AUTOFILL_EXTENSION || fileURLToPath(
  new URL("../../browser_extension/", import.meta.url),
);
const port = 19434;
const profile = fs.mkdtempSync(path.join(os.tmpdir(), "vault-edge-autofill-"));
let processHandle;

async function waitForJson(url, timeoutMs = 20000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      const response = await fetch(url);
      if (response.ok) return response.json();
    } catch {}
    await new Promise((resolve) => setTimeout(resolve, 250));
  }
  throw new Error(`Timed out waiting for ${url}`);
}

async function cdp(webSocketDebuggerUrl) {
  const socket = new WebSocket(webSocketDebuggerUrl);
  await new Promise((resolve, reject) => {
    socket.onopen = resolve;
    socket.onerror = reject;
  });
  let sequence = 0;
  const pending = new Map();
  const events = [];
  socket.onmessage = (event) => {
    const value = JSON.parse(event.data);
    if (value.id && pending.has(value.id)) {
      pending.get(value.id)(value);
      pending.delete(value.id);
    } else if (value.method) {
      events.push(value);
    }
  };
  return {
    events,
    call(method, params = {}) {
      return new Promise((resolve) => {
        const id = ++sequence;
        pending.set(id, resolve);
        socket.send(JSON.stringify({id, method, params}));
      });
    },
    close() { socket.close(); },
  };
}

try {
  assert.ok(fs.existsSync(edge) && fs.statSync(edge).isFile(), `Edge not found: ${edge}`);
  const manifestPath = path.join(extension, "manifest.json");
  assert.ok(fs.existsSync(manifestPath) && fs.statSync(manifestPath).isFile(), `Extension not found: ${extension}`);
  processHandle = spawn(edge, [
    `--user-data-dir=${profile}`,
    `--load-extension=${extension}`,
    `--disable-extensions-except=${extension}`,
    `--remote-debugging-port=${port}`,
    "--no-first-run",
    "--disable-default-apps",
    "about:blank",
  ], {stdio: "ignore", windowsHide: true});

  const version = await waitForJson(`http://127.0.0.1:${port}/json/version`);
  let targets = [];
  const workerDeadline = Date.now() + 15000;
  while (Date.now() < workerDeadline) {
    targets = await waitForJson(`http://127.0.0.1:${port}/json`);
    if (targets.some((target) => target.url === `chrome-extension://${extensionId}/background.js`)) break;
    await new Promise((resolve) => setTimeout(resolve, 300));
  }
  assert.ok(targets.some((target) => target.url === `chrome-extension://${extensionId}/background.js`));

  await fetch(`http://127.0.0.1:${port}/json/new?chrome-extension://${extensionId}/popup.html`, {method: "PUT"});
  let popup;
  const popupDeadline = Date.now() + 15000;
  while (Date.now() < popupDeadline) {
    targets = await waitForJson(`http://127.0.0.1:${port}/json`);
    popup = targets.find((target) => target.url === `chrome-extension://${extensionId}/popup.html`);
    if (popup) break;
    await new Promise((resolve) => setTimeout(resolve, 200));
  }
  assert.ok(popup);
  const popupCdp = await cdp(popup.webSocketDebuggerUrl);
  let popupResult;
  const hostDeadline = Date.now() + 30000;
  while (Date.now() < hostDeadline) {
    popupResult = await popupCdp.call("Runtime.evaluate", {
      expression: "document.querySelector('#status') && ({text:document.querySelector('#status').textContent,cls:document.querySelector('#status').className,formHidden:document.querySelector('#unlock-form').hidden,passwordType:document.querySelector('#master-password').type,passwordValue:document.querySelector('#master-password').value,logoLoaded:document.querySelector('header img').complete&&document.querySelector('header img').naturalWidth>0})",
      returnByValue: true,
    });
    const state = popupResult.result?.result?.value;
    if (state && (/本机宿主已连接/.test(state.text) || state.cls.includes("error"))) break;
    await new Promise((resolve) => setTimeout(resolve, 200));
  }
  assert.ok(popupResult.result?.result?.value, "The extension popup did not initialize");
  assert.match(popupResult.result.result.value.text, /本机宿主已连接/);
  assert.equal(popupResult.result.result.value.logoLoaded, true);
  if (/未解锁/.test(popupResult.result.result.value.text)) {
    assert.equal(popupResult.result.result.value.formHidden, false);
    assert.equal(popupResult.result.result.value.passwordType, "password");
    assert.equal(popupResult.result.result.value.passwordValue, "");
  }
  popupCdp.close();

  const page = targets.find((target) => target.type === "page" && target.url === "about:blank");
  assert.ok(page);
  const pageCdp = await cdp(page.webSocketDebuggerUrl);
  await pageCdp.call("Runtime.enable");
  await pageCdp.call("Page.enable");
  await pageCdp.call("Page.navigate", {url: "https://example.com"});
  await new Promise((resolve) => setTimeout(resolve, 4000));
  const context = pageCdp.events
    .filter((event) => event.method === "Runtime.executionContextCreated")
    .map((event) => event.params.context)
    .find((item) => item.origin === `chrome-extension://${extensionId}`);
  assert.ok(context, "content script isolated world was not created");
  const overlayResult = await pageCdp.call("Runtime.evaluate", {
    contextId: context.id,
    expression: `(() => {
      const form = document.createElement('form');
      const username = document.createElement('input');
      username.type = 'email'; username.autocomplete = 'username';
      const password = document.createElement('input');
      password.type = 'password'; password.style.cssText = 'width:200px;height:40px';
      form.append(username, password); document.body.appendChild(form);
      password.dispatchEvent(new FocusEvent('focusin', {bubbles:true}));
      return {active:activePassword === password, visible:anchor?.style.display, hasAnchor:Boolean(anchor)};
    })()`,
    returnByValue: true,
  });
  assert.deepEqual(overlayResult.result.result.value, {active: true, visible: "block", hasAnchor: true});
  await new Promise((resolve) => setTimeout(resolve, 700));
  const overlayLogo = await pageCdp.call("Runtime.evaluate", {
    contextId: context.id,
    expression: "(() => { const logo=panelRoot?.querySelector('.trigger img'); return {loaded:Boolean(logo?.complete&&logo?.naturalWidth>0),src:logo?.src||''}; })()",
    returnByValue: true,
  });
  assert.equal(overlayLogo.result.result.value.loaded, true, overlayLogo.result.result.value.src);
  pageCdp.close();

  const browserCdp = await cdp(version.webSocketDebuggerUrl);
  await browserCdp.call("Browser.close");
  browserCdp.close();
  console.log("browser extension integration test passed");
} finally {
  if (processHandle && processHandle.exitCode === null) {
    processHandle.kill();
    await Promise.race([
      new Promise((resolve) => processHandle.once("exit", resolve)),
      new Promise((resolve) => setTimeout(resolve, 3000)),
    ]);
  }
  if (path.resolve(profile).startsWith(path.resolve(os.tmpdir()) + path.sep)) {
    for (let attempt = 0; attempt < 10; attempt += 1) {
      try {
        fs.rmSync(profile, {recursive: true, force: true, maxRetries: 2, retryDelay: 100});
        break;
      } catch (error) {
        if (attempt === 9) console.warn(`temporary profile cleanup deferred: ${error.code}`);
        await new Promise((resolve) => setTimeout(resolve, 300));
      }
    }
  }
}
