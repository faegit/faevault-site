"use strict";

const runtime = (globalThis.browser || globalThis.chrome).runtime;
const statusNode = document.getElementById("status");
const form = document.getElementById("unlock-form");
const passwordInput = document.getElementById("master-password");
const unlockButton = document.getElementById("unlock");
const toggleButton = document.getElementById("toggle-password");
const hintNode = document.getElementById("hint");
const tr = (source) => globalThis.vaultTr?.(source) || source;
globalThis.localizeVaultDocument?.();

function send(action, values = {}) {
  const message = {action, ...values};
  if (globalThis.browser) {
    return runtime.sendMessage(message).catch((error) => ({
      ok: false,
      error: {message: String(error?.message || error || tr("无法连接扩展后台"))},
    }));
  }
  return new Promise((resolve) => runtime.sendMessage(message, (response) => {
    const error = runtime.lastError;
    resolve(error ? {ok: false, error: {message: error.message}} : response);
  }));
}

function showUnlock(visible) {
  form.hidden = !visible;
  document.getElementById("lock").hidden = visible;
  if (visible) requestAnimationFrame(() => passwordInput.focus());
}

async function refresh() {
  statusNode.className = "status";
  statusNode.textContent = tr("正在检测…");
  const response = await send("status");
  if (!response?.ok) {
    statusNode.className = "status error";
    statusNode.textContent = tr("未连接本机宿主");
    showUnlock(false);
    return;
  }
  globalThis.setVaultLocale?.(response.result.uiLocale);
  globalThis.localizeVaultDocument?.();
  statusNode.className = `status ${response.result.locked ? "" : "ok"}`;
  statusNode.textContent = tr(response.result.locked ? "本机宿主已连接，保险库未解锁" : "本机宿主已连接，保险库已解锁");
  showUnlock(Boolean(response.result.locked));
}

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  const masterPassword = passwordInput.value;
  if (!masterPassword) return;
  hintNode.textContent = "";
  unlockButton.disabled = true;
  passwordInput.disabled = true;
  unlockButton.textContent = tr("正在解锁…");
  let unlocked = false;
  try {
    const response = await send("unlock", {masterPassword});
    passwordInput.value = "";
    if (!response?.ok) {
      hintNode.textContent = response?.error?.message || tr("解锁失败");
      return;
    }
    statusNode.className = "status ok";
    statusNode.textContent = tr("解锁成功，正在打开账号列表");
    showUnlock(false);
    unlocked = true;
    setTimeout(() => window.close(), 350);
  } finally {
    passwordInput.value = "";
    passwordInput.disabled = false;
    unlockButton.disabled = false;
    unlockButton.textContent = tr("解锁并填充");
    if (!unlocked) passwordInput.focus();
  }
});

toggleButton.addEventListener("click", () => {
  const showing = passwordInput.type === "text";
  passwordInput.type = showing ? "password" : "text";
  toggleButton.title = tr(showing ? "显示主密码" : "隐藏主密码");
  toggleButton.setAttribute("aria-label", toggleButton.title);
  passwordInput.focus();
});

document.getElementById("refresh").addEventListener("click", refresh);
document.getElementById("lock").addEventListener("click", async () => {
  await send("lock");
  await refresh();
});
window.addEventListener("pagehide", () => { passwordInput.value = ""; });
refresh();
