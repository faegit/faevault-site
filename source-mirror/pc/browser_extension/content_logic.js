(function (root) {
  "use strict";

  function normalizeFieldText(value) {
    return String(value || "").normalize("NFKC")
      .replace(/([a-z0-9])([A-Z])/g, "$1 $2")
      .toLowerCase().replace(/[_\-]+/g, " ").replace(/\s+/g, " ").trim();
  }
  function autocompleteToken(field) {
    const tokens = String(field?.autocomplete || "").toLowerCase().trim().split(/\s+/);
    if (tokens[tokens.length - 1] === "webauthn") tokens.pop();
    return tokens[tokens.length - 1] || "";
  }
  const standardRoles = {
    email: "email", tel: "phone", "tel-national": "phone", "tel-local": "phone",
    name: "full_name", "street-address": "street_address", "address-line1": "street_address",
    "address-level1": "region", "address-level2": "city", country: "country", "country-name": "country",
    "postal-code": "postal_code", "cc-name": "cardholder", "cc-number": "card_number",
    "cc-exp": "card_expiry", "cc-csc": "card_cvv", username: "username",
    "current-password": "password", "one-time-code": "one_time_code",
  };
  function autocompleteRole(field) { return standardRoles[autocompleteToken(field)] || null; }
  const aliases = [
    ["one_time_code", /\b(?:otp|totp|2fa|two factor|verification code|auth code|one time code)\b|验证码|动态码|一次性密码/],
    ["wifi_password", /\b(?:wifi password|wi fi password|wireless password)\b|无线密码/],
    ["api_secret", /\b(?:api secret|client secret|apisecret)\b/],
    ["api_key", /\b(?:api key|apikey)\b/],
    ["recovery_answer", /\b(?:recovery answer|security answer)\b|密保答案/],
    ["card_number", /\b(?:card number|cardnumber|cc number)\b|银行卡号|卡号/],
    ["cardholder", /\b(?:card holder|cardholder|name on card)\b|持卡人/],
    ["card_expiry", /\b(?:card expiry|card expiration|expiration date|expiry date)\b|有效期/],
    ["card_cvv", /\b(?:cvv|cvc|card security code)\b|安全码/],
    ["id_number", /\b(?:id number|identity number|passport number)\b|身份证号|证件号码/],
    ["postal_code", /\b(?:postal code|postalcode|zip|zip code|zipcode)\b|邮编/],
    ["phone", /\b(?:phone|telephone|mobile|phone number)\b|手机号|电话/],
    ["email", /\b(?:email|e mail|email address)\b|邮箱|邮件/],
    ["full_name", /\b(?:full name|fullname|real name|realname)\b|姓名/],
    ["username", /\b(?:username|user name|login|login id|account|account name)\b|用户名|账号|帐号/],
    ["street_address", /\b(?:street address|address line1|address line 1)\b|街道地址|详细地址/],
    ["country", /\bcountry\b|国家/], ["region", /\b(?:region|province|state)\b|省份/],
    ["city", /\bcity\b|城市/], ["ssid", /\b(?:ssid|wifi name)\b/],
    ["host", /\b(?:hostname|host name|server host)\b/], ["port", /\b(?:port|server port)\b/],
    ["database", /\b(?:database|database name)\b/],
  ];
  function eligible(field) { return field && !field.disabled && !field.readOnly && field.visible !== false; }
  function autofillRole(field) {
    if (!eligible(field)) return null;
    const token = autocompleteToken(field);
    if (token === "new-password") return null;
    const standard = autocompleteRole(field);
    if (standard) return standard;
    // A declared standard field that we cannot represent must not fall back to contradictory labels.
    if (token && token !== "off" && token !== "on") return null;
    const markers = [field.name, field.id, field.labelText, field.ariaLabelledByText, field.ariaLabel, field.placeholder].map(normalizeFieldText);
    for (const marker of markers) {
      for (const [role, pattern] of aliases) if (pattern.test(marker)) return role;
    }
    return normalizeFieldText(field.type) === "password" ? "password" : null;
  }
  function usernameScore(field, passwordIndex, index) {
    if (!eligible(field) || !["text", "email", "tel", ""].includes(normalizeFieldText(field.type))) return -1;
    const role = autofillRole(field);
    if (role !== "username" && role !== "email" && normalizeFieldText(field.type) !== "email") return -1;
    return (autocompleteRole(field) === "username" ? 200 : role === "username" ? 100 : 80) + (index < passwordIndex ? 20 : 0);
  }
  function selectUsernameField(fields, passwordField) {
    const passwordIndex = fields.indexOf(passwordField);
    return fields.map((field, index) => ({field, index, score: usernameScore(field, passwordIndex, index)}))
      .filter((item) => item.score >= 0).sort((a, b) => b.score - a.score || b.index - a.index)[0]?.field || null;
  }
  function selectSavePassword(passwordFields) {
    const values = passwordFields.filter((field) => !field.disabled && !field.readOnly && field.value);
    if (!values.length) return {password: "", mismatch: false};
    const newFields = values.filter((field) => autocompleteToken(field) === "new-password");
    const selected = newFields.length ? newFields : values;
    if (selected.length > 1 && selected.some((field) => field.value !== selected[0].value)) return {password: "", mismatch: true};
    return {password: selected[0].value, mismatch: false};
  }
  function selectFillPasswordFields(passwordFields) {
    return passwordFields.filter((field) => eligible(field) && autocompleteToken(field) !== "new-password" && autofillRole({...field, type: field.type || "password"}) === "password");
  }
  const mappableRoles = new Set([
    ...Object.values(standardRoles), "id_number", "api_key", "api_secret", "host", "port", "database",
    "ssid", "wifi_password", "recovery_answer", "custom_text", "custom_secret",
  ]);
  function isMappableField(field) {
    if (!eligible(field)) return false;
    const token = autocompleteToken(field);
    return !token || token === "off" || token === "on";
  }
  function resolvedFieldRole(field, mappings, key) {
    const recognized = autofillRole(field);
    if (recognized) return recognized;
    if (!isMappableField(field) || !key || !mappings || !Object.prototype.hasOwnProperty.call(mappings, key)) return null;
    const mapped = mappings[key];
    return mappableRoles.has(mapped) ? mapped : null;
  }
  function isOtpField(field) { return autofillRole(field) === "one_time_code"; }
  root.VaultContentLogic = Object.freeze({normalizeFieldText, autocompleteRole, selectUsernameField, selectSavePassword, selectFillPasswordFields, isOtpField, autofillRole, isMappableField, resolvedFieldRole});
})(globalThis);
