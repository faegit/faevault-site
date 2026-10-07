"use strict";

const tr = (source) => globalThis.vaultTr?.(source) || source;

const extensionRuntime = (globalThis.browser || globalThis.chrome).runtime;
let activePassword = null;
let anchor = null;
let panel = null;
let panelRoot = null;
let otpCountdownTimer = null;

function send(message) {
  const finish = (resolve, response) => {
    if (response?.result?.uiLocale) globalThis.setVaultLocale?.(response.result.uiLocale);
    resolve(response);
  };
  return new Promise((resolve) => {
    if (globalThis.browser) {
      extensionRuntime.sendMessage(message)
        .then((response) => finish(resolve, response || {ok: false, error: {message: tr("扩展没有返回结果")}}))
        .catch((error) => resolve({ok: false, error: {message: String(error?.message || error)}}));
      return;
    }
    extensionRuntime.sendMessage(message, (response) => {
      const runtimeError = extensionRuntime.lastError;
      if (runtimeError) resolve({ok: false, error: {message: runtimeError.message}});
      else finish(resolve, response || {ok: false, error: {message: tr("扩展没有返回结果")}});
    });
  });
}

function isVisible(field) {
  const style = getComputedStyle(field);
  const rect = field.getBoundingClientRect();
  return style.display !== "none" && style.visibility !== "hidden" && rect.width > 0 && rect.height > 0;
}

function formFields(passwordField) {
  const root = passwordField.form || passwordField.getRootNode();
  return [...root.querySelectorAll("input,textarea")].filter(isVisible);
}

function passwordFields(passwordField) {
  return formFields(passwordField).filter((field) => field.type === "password");
}

function otpFields(activeField) {
  return formFields(activeField).filter((field) => VaultContentLogic.isOtpField(fieldDescription(field)));
}

function fieldDescription(field) {
  return {
    type: field.type,
    autocomplete: field.autocomplete,
    name: field.name,
    id: field.id,
    placeholder: field.placeholder,
    ariaLabel: field.getAttribute("aria-label"),
    labelText: [...(field.labels || [])].map((label) => label.textContent || "").join(" "),
    ariaLabelledByText: (field.getAttribute("aria-labelledby") || "").split(/\s+/).map((id) => field.getRootNode().getElementById?.(id)?.textContent || "").join(" "),
    disabled: field.disabled,
    readOnly: field.readOnly,
    visible: isVisible(field),
    value: field.value,
    node: field,
  };
}

function setNativeValue(field, value) {
  const prototype = field instanceof HTMLTextAreaElement ? HTMLTextAreaElement.prototype : HTMLInputElement.prototype;
  const setter = Object.getOwnPropertyDescriptor(prototype, "value")?.set;
  if (setter) setter.call(field, value);
  else field.value = value;
  field.dispatchEvent(new InputEvent("input", {bubbles: true, inputType: "insertReplacementText", data: null}));
  field.dispatchEvent(new Event("change", {bubbles: true}));
}

function ensureUi() {
  if (anchor) return;
  anchor = document.createElement("div");
  anchor.style.cssText = "all:initial;position:fixed;z-index:2147483647;display:none";
  const shadow = anchor.attachShadow({mode: "closed"});
  panelRoot = shadow;
  const style = document.createElement("style");
  style.textContent = `
    :host{all:initial}button{font:13px/1.2 system-ui,sans-serif;letter-spacing:0;border:0;cursor:pointer}
    .trigger{width:30px;height:30px;padding:0;border-radius:7px;background:#232631;box-shadow:0 3px 12px #0003;overflow:hidden}.trigger img{display:block;width:30px;height:30px}
    .panel{position:absolute;right:0;top:36px;width:290px;max-height:330px;overflow:auto;padding:8px;background:#fff;color:#20232b;border:1px solid #dfe2ea;border-radius:8px;box-shadow:0 10px 30px #0003;font:13px/1.35 system-ui,sans-serif}
    .head{padding:7px 8px;font-weight:700}.item,.command{display:block;width:100%;padding:9px;text-align:left;border-radius:6px;background:transparent;color:#20232b}.item:hover,.command:hover{background:#eef0fe}
    .authorize{margin-top:8px;background:#e8f0ff;color:#1757a6;font-weight:650;text-align:center}.authorize:hover,.authorize:focus-visible{background:#d9e8ff;outline:2px solid #78a9e6;outline-offset:1px}
    .account{display:block;margin-top:2px;color:#697083;overflow:hidden;text-overflow:ellipsis}.otp{display:flex;align-items:center;gap:7px;margin-top:5px;color:#087f73;font:600 14px/1.2 ui-monospace,SFMono-Regular,Consolas,monospace;letter-spacing:1px}.otp-time{color:#697083;font:11px/1.2 system-ui,sans-serif;letter-spacing:0}.status{padding:10px;color:#697083}.error{color:#c7373d}.divider{height:1px;background:#e7e9ef;margin:5px 0}
  `;
  shadow.appendChild(style);
  const trigger = document.createElement("button");
  trigger.className = "trigger";
  trigger.type = "button";
  trigger.title = tr("保险库自动填充");
  const triggerLogo = document.createElement("img");
  triggerLogo.src = extensionRuntime.getURL("icons/icon32.png");
  triggerLogo.alt = "";
  trigger.appendChild(triggerLogo);
  trigger.addEventListener("mousedown", (event) => event.preventDefault());
  trigger.addEventListener("click", () => togglePanel(shadow));
  shadow.appendChild(trigger);
  document.documentElement.appendChild(anchor);
}

function positionUi() {
  if (!anchor || !activePassword || !activePassword.isConnected) return hideUi();
  const rect = activePassword.getBoundingClientRect();
  anchor.style.left = `${Math.max(4, rect.right - 34)}px`;
  anchor.style.top = `${Math.max(4, rect.top + (rect.height - 30) / 2)}px`;
}

function hideUi() {
  if (otpCountdownTimer) clearInterval(otpCountdownTimer);
  otpCountdownTimer = null;
  if (anchor) anchor.style.display = "none";
  panel?.remove();
  panel = null;
  activePassword = null;
}

function status(panelNode, message, error = false) {
  panelNode.replaceChildren();
  const line = document.createElement("div");
  line.className = `status${error ? " error" : ""}`;
  line.textContent = message;
  panelNode.appendChild(line);
}

function authorizationRequired(panelNode, message, shadow) {
  status(panelNode, message || tr("此 IP 地址尚未授权自动填充"), true);
  const authorize = document.createElement("button");
  authorize.className = "command authorize";
  authorize.type = "button";
  authorize.textContent = tr("允许授权");
  authorize.setAttribute("aria-label", tr("允许此 IP 地址自动填充"));
  authorize.addEventListener("click", async () => {
    authorize.disabled = true;
    status(panelNode, tr("请在 PC 端确认此 IP 来源…"));
    const response = await send({action: "authorize"});
    if (!response.ok) {
      authorizationRequired(panelNode, response.error?.message || tr("授权未完成"), shadow);
      return;
    }
    panel?.remove();
    panel = null;
    await togglePanel(shadow);
  });
  panelNode.appendChild(authorize);
  authorize.focus();
}

async function togglePanel(shadow, autoFillSingle = false) {
  if (panel) {
    if (otpCountdownTimer) clearInterval(otpCountdownTimer);
    otpCountdownTimer = null;
    panel.remove();
    panel = null;
    return;
  }
  panel = document.createElement("div");
  panel.className = "panel";
  shadow.appendChild(panel);
  status(panel, tr("正在连接保险库…"));
  const response = await send({action: "list"});
  if (!panel) return;
  if (!response.ok) {
    if (response.error?.code === "ORIGIN_NOT_AUTHORIZED") {
      return authorizationRequired(panel, response.error?.message, shadow);
    }
    return status(panel, response.error?.message || tr("无法连接保险库"), true);
  }
  if (response.result.excluded) {
    hideUi();
    return;
  }
  const credentials = response.result.credentials || [];
  if (autoFillSingle && activePassword?.type === "password" && credentials.length === 1 && !credentials[0].requiresSelection) {
    await fillCredential(credentials[0].id);
    return;
  }
  renderCredentials(panel, credentials);
}

function renderCredentials(panelNode, credentials, query = "") {
  if (otpCountdownTimer) clearInterval(otpCountdownTimer);
  otpCountdownTimer = null;
  panelNode.replaceChildren();
  const head = document.createElement("div");
  head.className = "head";
  head.textContent = tr("登录账号");
  panelNode.appendChild(head);
  const search = document.createElement("input");
  search.type = "search";
  search.placeholder = tr("搜索保险库条目");
  search.value = query;
  search.addEventListener("keydown", async (event) => {
    if (event.key !== "Enter") return;
    event.preventDefault();
    const response = await send({action: "list", query: search.value.trim().slice(0, 80)});
    if (panel === panelNode && response.ok) renderCredentials(panelNode, response.result.credentials || [], search.value);
  });
  panelNode.appendChild(search);
  if (!credentials.length) status(panelNode, tr("此网站没有匹配条目"));
  for (const credential of credentials) {
    const button = document.createElement("button");
    button.className = "item";
    button.type = "button";
    const title = document.createElement("span");
    title.textContent = credential.title || credential.username || tr("登录条目");
    const account = document.createElement("span");
    account.className = "account";
    account.textContent = credential.username || tr("未填写用户名");
    button.append(title, account);
    const reason = document.createElement("span");
    reason.className = "account";
    const reasons = {confirmed: "已记住关联", exact: "网址匹配", same_site: "同站点候选", name: "名称相关", manual: "手动搜索"};
    reason.textContent = tr(reasons[credential.matchReason] || "网址匹配");
    button.appendChild(reason);
    if (credential.otp?.code) {
      const code = document.createElement("span");
      code.className = "otp";
      code.textContent = String(credential.otp.code).replace(/(.{3})(?=.)/, "$1 ");
      if (Number.isFinite(credential.otp.remaining)) {
        const remaining = document.createElement("span");
        remaining.className = "otp-time";
        remaining.textContent = `${credential.otp.remaining}s`;
        if (credential.otp.expiresAt) remaining.dataset.expiresAt = String(credential.otp.expiresAt);
        code.appendChild(remaining);
      }
      button.appendChild(code);
    }
    button.addEventListener("mousedown", (event) => event.preventDefault());
    button.addEventListener("click", () => fillCredential(credential.id, Boolean(credential.manualSelection)));
    panelNode.appendChild(button);
  }
  if (activePassword && passwordFields(activePassword).length) {
    const divider = document.createElement("div");
    divider.className = "divider";
    panelNode.appendChild(divider);
    const save = document.createElement("button");
    save.className = "command";
    save.type = "button";
    save.textContent = tr("保存当前填写内容");
    save.addEventListener("mousedown", (event) => event.preventDefault());
    save.addEventListener("click", saveCurrent);
    panelNode.appendChild(save);
  }
  const timedCodes = [...panelNode.querySelectorAll(".otp-time[data-expires-at]")];
  if (timedCodes.length) {
    otpCountdownTimer = setInterval(async () => {
      let expired = false;
      for (const label of timedCodes) {
        const remaining = Math.max(0, Math.ceil((Number(label.dataset.expiresAt) - Date.now()) / 1000));
        label.textContent = `${remaining}s`;
        expired ||= remaining === 0;
      }
      if (expired && panel === panelNode) {
        clearInterval(otpCountdownTimer);
        otpCountdownTimer = null;
        const response = await send({action: "list"});
        if (panel === panelNode && response.ok && !response.result.excluded) {
          renderCredentials(panelNode, response.result.credentials || []);
        }
      }
    }, 1000);
  }
}

async function fillCredential(credentialId, manualSelection = false) {
  if (!activePassword) return;
  status(panel, tr("正在读取凭据…"));
  const response = await send({action: "get", credentialId, manualSelection});
  if (!response.ok) return status(panel, response.error?.message || tr("读取失败"), true);
  const fields = formFields(activePassword);
  const descriptions = fields.map(fieldDescription);
  const passwordDescription = descriptions.find((item) => item.node === activePassword);
  const usernameDescription = VaultContentLogic.selectUsernameField(descriptions, passwordDescription);
  if (usernameDescription && response.result.username) setNativeValue(usernameDescription.node, response.result.username);
  const fillPasswords = VaultContentLogic.selectFillPasswordFields(
    passwordFields(activePassword).map(fieldDescription),
  );
  if (response.result.password) {
    for (const field of fillPasswords) setNativeValue(field.node, response.result.password);
  }
  const otpTargets = otpFields(activePassword);
  if (response.result.otp?.code) {
    for (const field of otpTargets) setNativeValue(field, response.result.otp.code);
  }
  const roleValues = response.result.fields || {};
  for (const description of descriptions) {
    const effectiveRole = VaultContentLogic.resolvedFieldRole(description, response.result.fieldMappings, fieldKey(description.node));
    const effectiveValue = effectiveRole === "one_time_code" ? response.result.otp?.code || roleValues.one_time_code : roleValues[effectiveRole];
    if (effectiveRole && effectiveValue) setNativeValue(description.node, effectiveValue);
  }
  const unknown = descriptions.filter((item) => !VaultContentLogic.autofillRole(item) && VaultContentLogic.isMappableField(item) && fieldKey(item.node));
  if (unknown.length) return renderFieldMapping(panel, credentialId, unknown, roleValues);
  panel?.remove();
  if (otpCountdownTimer) clearInterval(otpCountdownTimer);
  otpCountdownTimer = null;
  panel = null;
  activePassword.focus();
}

function fieldKey(field) {
  const key = JSON.stringify([location.pathname, field.type || "text", field.id || "", field.name || ""]);
  const siblings = formFields(field).filter((item) => item.type === field.type && item.id === field.id && item.name === field.name);
  return key.length <= 256 && siblings.length === 1 ? key : "";
}

function renderFieldMapping(panelNode, credentialId, unknown, values) {
  status(panelNode, tr("已填充可识别字段；其他输入框可手动映射"));
  const field = document.createElement("select");
  for (const description of unknown) {
    const option = document.createElement("option");
    option.value = fieldKey(description.node);
    option.textContent = description.labelText || description.ariaLabel || description.placeholder || description.name || description.id || tr("未识别输入框");
    field.appendChild(option);
  }
  const role = document.createElement("select");
  const labels = {username:"账号", password:"密码", custom_text:"自定义文本", custom_secret:"自定义密码", email:"邮箱", one_time_code:"动态码"};
  for (const name of Object.keys(values)) {
    const option = document.createElement("option"); option.value = name; option.textContent = tr(labels[name] || name); role.appendChild(option);
  }
  const save = document.createElement("button"); save.className = "command"; save.textContent = tr("记住输入框映射");
  save.disabled = !role.options.length;
  save.addEventListener("click", async () => {
    const response = await send({action:"map_field",credentialId,fieldKey:field.value,fieldRole:role.value});
    if (!response.ok) return status(panelNode,response.error?.message || tr("映射保存失败"),true);
    const target = unknown.find((description) => fieldKey(description.node) === field.value);
    if (target && values[role.value]) setNativeValue(target.node,values[role.value]);
    status(panelNode,tr("输入框映射已保存"));
  });
  const clear = document.createElement("button"); clear.className = "command"; clear.textContent = tr("移除输入框映射");
  clear.addEventListener("click", async () => {
    const response = await send({action:"map_field",credentialId,fieldKey:field.value,fieldRole:""});
    status(panelNode,response.ok ? tr("输入框映射已移除") : response.error?.message || tr("映射保存失败"),!response.ok);
  });
  panelNode.append(field,role,save,clear);
}

async function saveCurrent() {
  if (!activePassword) return;
  const fields = formFields(activePassword);
  const descriptions = fields.map(fieldDescription);
  const passwordDescription = descriptions.find((item) => item.node === activePassword);
  const username = VaultContentLogic.selectUsernameField(descriptions, passwordDescription)?.value || "";
  const selected = VaultContentLogic.selectSavePassword(passwordFields(activePassword).map(fieldDescription));
  if (selected.mismatch) return status(panel, tr("两次输入的密码不一致"), true);
  if (!selected.password) return status(panel, tr("密码为空，无法保存"), true);
  status(panel, tr("请在本机窗口确认保存…"));
  const response = await send({action: "save", title: document.title.slice(0, 256), username, password: selected.password});
  if (!response.ok) return status(panel, response.error?.message || tr("保存失败"), true);
  const labels = {created: tr("已新建登录条目"), updated: tr("已更新登录条目"), unchanged: tr("凭据没有变化"), cancelled: tr("已取消保存")};
  status(panel, labels[response.result.status] || tr("操作完成"));
}

document.addEventListener("focusin", (event) => {
  const field = event.composedPath().find((node) => node instanceof HTMLInputElement || node instanceof HTMLTextAreaElement) || event.target;
  if (!(field instanceof HTMLInputElement || field instanceof HTMLTextAreaElement) || !isVisible(field) || field.disabled || field.readOnly) return;
  const description = fieldDescription(field);
  if (["hidden", "button", "submit", "checkbox", "radio", "file", "search"].includes(field.type)) return;
  ensureUi();
  activePassword = field;
  anchor.style.display = "block";
  positionUi();
}, true);

document.addEventListener("focusout", () => setTimeout(() => {
  if (!panel && document.activeElement !== activePassword) hideUi();
}, 150), true);
window.addEventListener("scroll", positionUi, true);
window.addEventListener("resize", positionUi);

extensionRuntime.onMessage.addListener((message) => {
  if (message?.action !== "autofillUnlocked" || !activePassword || !panelRoot) return;
  panel?.remove();
  panel = null;
  togglePanel(panelRoot, true);
});
