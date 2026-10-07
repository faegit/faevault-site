"use strict";

const VAULT_ENGLISH = {
  "请确认当前网站可以接收所选条目的填充内容。": "Confirm that this website may receive the selected item’s autofill data.",
  "记住此网站与条目的关联": "Remember this website association",
  "允许填充": "Allow fill",
  "确认输入框映射": "Confirm field mapping",
  "此设置仅适用于当前网站和所选条目。": "This setting applies only to this website and the selected item.",
  "移除映射": "Remove mapping",
  "记住此程序与条目的关联": "Remember this application association",
  "已记住关联": "Remembered association",
  "程序匹配": "Application match",
  "名称相关": "Related name",
  "手动搜索": "Manual search",
  "搜索保险库条目": "Search vault items",
  "网址匹配": "Website match",
  "同站点候选": "Same-site candidate",
  "已填充可识别字段；其他输入框可手动映射": "Recognized fields filled; map other fields manually",
  "未识别输入框": "Unrecognized field",
  "账号": "Account",
  "密码": "Password",
  "自定义文本": "Custom text",
  "自定义密码": "Custom password",
  "邮箱": "Email",
  "记住输入框映射": "Remember field mapping",
  "映射保存失败": "Could not save mapping",
  "输入框映射已保存": "Field mapping saved",
  "移除输入框映射": "Remove field mapping",
  "输入框映射已移除": "Field mapping removed",

  "保险库自动填充": "Vault Autofill",
  "正在检测…": "Checking…",
  "主密码": "Master password",
  "显示主密码": "Show master password",
  "隐藏主密码": "Hide master password",
  "解锁并填充": "Unlock and fill",
  "重新检测": "Check again",
  "锁定浏览器会话": "Lock browser session",
  "无法连接扩展后台": "Could not connect to the extension background",
  "未连接本机宿主": "Desktop host not connected",
  "本机宿主已连接，保险库未解锁": "Desktop host connected; vault locked",
  "本机宿主已连接，保险库已解锁": "Desktop host connected; vault unlocked",
  "正在解锁…": "Unlocking…",
  "解锁失败": "Could not unlock",
  "解锁成功，正在打开账号列表": "Vault unlocked. Opening logins…",
  "无法连接本机保险库": "Could not connect to the local vault",
  "本机保险库操作失败": "The local vault operation failed",
  "本机保险库响应超时": "The local vault response timed out",
  "只能从扩展弹窗解锁保险库": "The vault can only be unlocked from the extension popup",
  "自动填充操作失败": "The autofill operation failed",
  "此 IP 地址尚未授权自动填充": "This IP address is not authorized for autofill",
  "允许授权": "Authorize",
  "允许此 IP 地址自动填充": "Allow autofill for this IP address",
  "请在 PC 端确认此 IP 来源…": "Confirm this IP origin in the desktop app…",
  "授权未完成": "Authorization was not completed",
  "正在连接保险库…": "Connecting to vault…",
  "无法连接保险库": "Could not connect to vault",
  "登录账号": "Logins",
  "此网站没有匹配条目": "No matching items for this website",
  "登录条目": "Login item",
  "未填写用户名": "No username",
  "动态码": "One-time code",
  "保存当前填写内容": "Save current form",
  "正在读取凭据…": "Reading login…",
  "读取失败": "Could not read login",
  "两次输入的密码不一致": "The password fields do not match",
  "密码为空，无法保存": "The password is empty and cannot be saved",
  "请在本机窗口确认保存…": "Confirm saving in the desktop window…",
  "保存失败": "Could not save",
  "已新建登录条目": "Login item created",
  "已更新登录条目": "Login item updated",
  "凭据没有变化": "The login did not change",
  "已取消保存": "Saving canceled",
  "操作完成": "Done",
  "扩展没有返回结果": "The extension did not return a result",
};

let vaultLocale = (
  (globalThis.navigator?.language || "").toLowerCase().startsWith("en") ? "en" : "zh-Hans"
);

globalThis.setVaultLocale = function setVaultLocale(locale) {
  vaultLocale = locale === "en" ? "en" : "zh-Hans";
};

globalThis.vaultTr = function vaultTr(source) {
  return vaultLocale === "en" ? (VAULT_ENGLISH[source] || source) : source;
};

globalThis.localizeVaultDocument = function localizeVaultDocument(root = document) {
  if (vaultLocale !== "en") return;
  root.title = globalThis.vaultTr(root.title);
  const walker = root.createTreeWalker(root.body, NodeFilter.SHOW_TEXT);
  let node;
  while ((node = walker.nextNode())) {
    const value = node.nodeValue.trim();
    if (value && VAULT_ENGLISH[value]) {
      node.nodeValue = node.nodeValue.replace(value, VAULT_ENGLISH[value]);
    }
  }
  root.querySelectorAll("[title], [aria-label], [placeholder]").forEach((element) => {
    for (const attribute of ["title", "aria-label", "placeholder"]) {
      if (element.hasAttribute(attribute)) {
        element.setAttribute(attribute, globalThis.vaultTr(element.getAttribute(attribute)));
      }
    }
  });
};
