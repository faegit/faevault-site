(function (root) {
  "use strict";

  const ACTIONS = new Set(["status", "unlock", "list", "get", "save", "authorize", "lock", "map_field"]);

  function normalizeBrowserOrigin(raw) {
    if (typeof raw !== "string" || raw.length > 2048) throw new Error("INVALID_ORIGIN");
    const url = new URL(raw);
    if (url.protocol !== "https:" || !url.hostname || url.username || url.password) {
      throw new Error("INVALID_ORIGIN");
    }
    return url.origin;
  }

  function validateContentMessage(message) {
    if (!message || typeof message !== "object" || !ACTIONS.has(message.action)) {
      throw new Error("INVALID_REQUEST");
    }
    const result = {action: message.action};
    if (message.action === "unlock") {
      if (typeof message.masterPassword !== "string" || !message.masterPassword || message.masterPassword.length > 128) {
        throw new Error("INVALID_REQUEST");
      }
      result.masterPassword = message.masterPassword;
    }
    if (message.action === "list" && message.query !== undefined) {
      if (typeof message.query !== "string" || message.query.length > 80) throw new Error("INVALID_REQUEST");
      result.query = message.query;
    }
    if (message.action === "get" || message.action === "map_field") {
      if (typeof message.credentialId !== "string" || !message.credentialId || message.credentialId.length > 128) {
        throw new Error("INVALID_REQUEST");
      }
      result.credentialId = message.credentialId;
      if (message.action === "get" && message.manualSelection !== undefined) {
        if (typeof message.manualSelection !== "boolean") throw new Error("INVALID_REQUEST");
        result.manualSelection = message.manualSelection;
      }
      if (message.action === "map_field") {
        if (typeof message.fieldKey !== "string" || !message.fieldKey || message.fieldKey.length > 256 || typeof message.fieldRole !== "string" || message.fieldRole.length > 40) throw new Error("INVALID_REQUEST");
        result.fieldKey = message.fieldKey; result.fieldRole = message.fieldRole;
      }
    }
    if (message.action === "save") {
      for (const [key, maximum] of [["title", 256], ["username", 512], ["password", 4096]]) {
        if (typeof message[key] !== "string" || message[key].length > maximum) throw new Error("INVALID_REQUEST");
        result[key] = message[key];
      }
      if (!result.password) throw new Error("INVALID_REQUEST");
    }
    return result;
  }

  root.VaultProtocol = Object.freeze({normalizeBrowserOrigin, validateContentMessage});
})(globalThis);
