(function (root) {
  "use strict";

  function text(value) {
    return String(value || "").toLowerCase();
  }

  function usernameScore(field, passwordIndex, index) {
    const type = text(field.type);
    if (!["text", "email", "tel", ""].includes(type) || field.disabled || field.readOnly) return -1;
    const marker = [field.autocomplete, field.name, field.id, field.placeholder, field.ariaLabel].map(text).join(" ");
    let score = index < passwordIndex ? 20 : 0;
    if (marker.includes("username") || marker.includes("user") || marker.includes("login") || marker.includes("account")) score += 100;
    if (type === "email" || marker.includes("email")) score += 80;
    if (field.visible !== false) score += 10;
    return score;
  }

  function selectUsernameField(fields, passwordField) {
    const passwordIndex = fields.indexOf(passwordField);
    return fields
      .map((field, index) => ({field, index, score: usernameScore(field, passwordIndex, index)}))
      .filter((item) => item.score >= 0)
      .sort((a, b) => b.score - a.score || b.index - a.index)[0]?.field || null;
  }

  function selectSavePassword(passwordFields) {
    const values = passwordFields.filter((field) => !field.disabled && !field.readOnly && field.value);
    if (!values.length) return {password: "", mismatch: false};
    const newFields = values.filter((field) => text(field.autocomplete) === "new-password");
    const selected = newFields.length ? newFields : values;
    if (selected.length > 1 && selected.some((field) => field.value !== selected[0].value)) {
      return {password: "", mismatch: true};
    }
    return {password: selected[0].value, mismatch: false};
  }

  function selectFillPasswordFields(passwordFields) {
    return passwordFields.filter((field) => {
      if (field.disabled || field.readOnly) return false;
      return text(field.autocomplete) !== "new-password";
    });
  }

  function isOtpField(field) {
    if (!field || field.disabled || field.readOnly || field.visible === false) return false;
    const autocomplete = text(field.autocomplete);
    if (autocomplete === "one-time-code") return true;
    const marker = [field.name, field.id, field.placeholder, field.ariaLabel].map(text).join(" ");
    return ["otp", "totp", "2fa", "two-factor", "verification code", "auth code", "验证码", "动态码", "一次性密码"]
      .some((token) => marker.includes(token));
  }

  function autofillRole(field) {
    if (!field || field.disabled || field.readOnly || field.visible === false) return null;
    const autocomplete = text(field.autocomplete).replace(/[^a-z0-9-]/g, "");
    const exact = {
      email: "email", tel: "phone", name: "full_name", "street-address": "street_address",
      "address-line1": "street_address", "address-level1": "region", "address-level2": "city",
      country: "country", "country-name": "country", "postal-code": "postal_code",
      "cc-name": "cardholder", "cc-number": "card_number", "cc-exp": "card_expiry", "cc-csc": "card_cvv",
      username: "username", "current-password": "password", "one-time-code": "one_time_code",
    };
    if (exact[autocomplete]) return exact[autocomplete];
    const marker = [field.name, field.id, field.placeholder, field.ariaLabel].map(text).join(" ");
    if (/postal|zip|邮编/.test(marker)) return "postal_code";
    if (/phone|telephone|手机号|电话/.test(marker)) return "phone";
    if (/email|邮箱|邮件/.test(marker)) return "email";
    if (/full.?name|real.?name|姓名/.test(marker)) return "full_name";
    if (/card.?number|银行卡号|卡号/.test(marker)) return "card_number";
    if (/cvv|cvc|安全码/.test(marker)) return "card_cvv";
    if (isOtpField(field)) return "one_time_code";
    return null;
  }

  root.VaultContentLogic = Object.freeze({selectUsernameField, selectSavePassword, selectFillPasswordFields, isOtpField, autofillRole});
})(globalThis);
