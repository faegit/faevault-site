"use strict";

if (typeof importScripts === "function" && !globalThis.vaultTr) importScripts("i18n.js");
const tr = (source) => globalThis.vaultTr?.(source) || source;

if (typeof importScripts === "function" && !globalThis.VaultProtocol) importScripts("protocol.js");

const extensionApi = globalThis.browser || globalThis.chrome;
const HOST_NAME = "app.fae.vault.autofill";
let nativePort = null;
const pending = new Map();

function disconnectError() {
  const detail = extensionApi.runtime.lastError?.message || tr("无法连接本机保险库");
  return {code: "HOST_UNAVAILABLE", message: detail, retryable: true};
}

function closePort(error) {
  nativePort = null;
  for (const {reject, timer} of pending.values()) {
    clearTimeout(timer);
    reject(error);
  }
  pending.clear();
}

function ensurePort() {
  if (nativePort) return nativePort;
  nativePort = extensionApi.runtime.connectNative(HOST_NAME);
  nativePort.onMessage.addListener((message) => {
    const item = pending.get(message?.requestId);
    if (!item) return;
    pending.delete(message.requestId);
    clearTimeout(item.timer);
    if (message.ok) {
      if (message.result?.uiLocale) globalThis.setVaultLocale?.(message.result.uiLocale);
      item.resolve(message.result || {});
    }
    else item.reject(message.error || {code: "HOST_ERROR", message: tr("本机保险库操作失败"), retryable: true});
  });
  nativePort.onDisconnect.addListener(() => closePort(disconnectError()));
  return nativePort;
}

function nativeRequest(action, values = {}) {
  return new Promise((resolve, reject) => {
    const requestId = crypto.randomUUID();
    const timer = setTimeout(() => {
      pending.delete(requestId);
      reject({code: "TIMEOUT", message: tr("本机保险库响应超时"), retryable: true});
    }, 120000);
    pending.set(requestId, {resolve, reject, timer});
    try {
      ensurePort().postMessage({version: 1, requestId, action, ...values});
    } catch (error) {
      pending.delete(requestId);
      clearTimeout(timer);
      reject({code: "HOST_UNAVAILABLE", message: String(error?.message || error), retryable: true});
    }
  });
}

function notifyActiveTabUnlocked() {
  if (!extensionApi.tabs) return;
  if (globalThis.browser) {
    extensionApi.tabs.query({active: true, currentWindow: true})
      .then((tabs) => Promise.allSettled(tabs.map((tab) => extensionApi.tabs.sendMessage(tab.id, {action: "autofillUnlocked"}))))
      .catch(() => {});
    return;
  }
  extensionApi.tabs.query({active: true, currentWindow: true}, (tabs) => {
    for (const tab of tabs || []) {
      extensionApi.tabs.sendMessage(tab.id, {action: "autofillUnlocked"}, () => void extensionApi.runtime.lastError);
    }
  });
}

async function handleMessage(message, sender) {
  const clean = VaultProtocol.validateContentMessage(message);
  if (clean.action === "status" || clean.action === "lock") return nativeRequest(clean.action);
  if (clean.action === "unlock") {
    const extensionRoot = extensionApi.runtime.getURL("");
    if (!sender?.url?.startsWith(extensionRoot) || sender?.tab) {
      throw {code: "UNAUTHORIZED", message: tr("只能从扩展弹窗解锁保险库"), retryable: false};
    }
    const result = await nativeRequest("unlock", {masterPassword: clean.masterPassword});
    notifyActiveTabUnlocked();
    return result;
  }
  const senderUrl = sender?.url || sender?.tab?.url;
  const origin = VaultProtocol.normalizeBrowserOrigin(senderUrl);
  const {action, ...payload} = clean;
  return nativeRequest(action, {...payload, origin});
}

extensionApi.runtime.onMessage.addListener((message, sender, sendResponse) => {
  handleMessage(message, sender)
    .then((result) => sendResponse({ok: true, result}))
    .catch((error) => sendResponse({ok: false, error: {
      code: error?.code || error?.message || "REQUEST_FAILED",
      message: error?.message || tr("自动填充操作失败"),
      retryable: Boolean(error?.retryable),
    }}));
  return true;
});
