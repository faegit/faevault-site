package com.vault.autofill

import android.text.InputType

object FieldClassifier {
    private const val MAX_FIELDS = 8

    fun classify(evidence: FieldEvidence): FieldClassification {
        if (!evidence.visible || !evidence.enabled) return FieldClassification(FieldKind.UNKNOWN, 0)

        val scores = mutableMapOf<FieldKind, Int>()
        fun score(kind: FieldKind, value: Int) {
            scores[kind] = maxOf(scores[kind] ?: 0, value)
        }

        evidence.autofillHints.forEach { hint ->
            hintKind(hint)?.let { score(it, 100) }
        }
        evidence.htmlAttributes["autocomplete"]
            ?.split(Regex("\\s+"))
            ?.forEach { hintKind(it)?.let { kind -> score(kind, 100) } }

        evidence.htmlAttributes["type"]?.let { htmlType ->
            when (normalize(htmlType)) {
                "password" -> score(FieldKind.PASSWORD, 95)
                "email" -> score(FieldKind.EMAIL, 90)
            }
        }

        val variation = evidence.inputType and InputType.TYPE_MASK_VARIATION
        val isText = evidence.inputType == 0 ||
            evidence.inputType and InputType.TYPE_MASK_CLASS == InputType.TYPE_CLASS_TEXT
        val isPassword = variation in setOf(
            InputType.TYPE_TEXT_VARIATION_PASSWORD,
            InputType.TYPE_TEXT_VARIATION_VISIBLE_PASSWORD,
            InputType.TYPE_TEXT_VARIATION_WEB_PASSWORD,
        )
        if (isPassword) score(FieldKind.PASSWORD, 90)
        if (variation in setOf(InputType.TYPE_TEXT_VARIATION_EMAIL_ADDRESS, InputType.TYPE_TEXT_VARIATION_WEB_EMAIL_ADDRESS)) {
            score(FieldKind.EMAIL, 80)
        }

        if (isText) {
            fun scoreToken(raw: String?, ordinaryScore: Int) {
                tokenKind(raw)?.let { kind -> score(kind, if (kind.isSpecialized()) 96 else ordinaryScore) }
            }
            scoreToken(evidence.resourceId, 50)
            scoreToken(evidence.htmlAttributes["name"], 70)
            scoreToken(evidence.htmlAttributes["id"], 65)
            scoreToken(evidence.htmlAttributes["placeholder"], 60)
            scoreToken(evidence.htmlAttributes["aria-label"], 60)
            scoreToken(evidence.htmlAttributes["title"], 55)
            scoreToken(evidence.htmlAttributes["data-label"], 55)
            scoreToken(evidence.label, 40)
            tokenKind(evidence.className)?.let { score(it, 10) }
        }

        if (isPassword) {
            scores.keys.filter { it == FieldKind.USERNAME || it == FieldKind.EMAIL }.forEach(scores::remove)
        }
        if (scores.isEmpty()) return FieldClassification(FieldKind.UNKNOWN, 0)
        val best = scores.maxOf { it.value }
        val winners = scores.filterValues { it == best }.keys
        return if (winners.size == 1) FieldClassification(winners.first(), best)
        else FieldClassification(FieldKind.UNKNOWN, 0)
    }

    fun <T> selectFields(candidates: List<FieldCandidate<T>>, manualRequest: Boolean): List<ClassifiedField<T>> {
        val classified = candidates.filter { it.evidence.visible && it.evidence.enabled }.map { candidate ->
            val result = classify(candidate.evidence)
            ClassifiedField(
                id = candidate.id,
                kind = result.kind,
                score = result.score,
                focused = candidate.evidence.focused,
                currentText = candidate.evidence.currentText,
                fieldKey = candidate.evidence.fieldKey,
                label = candidate.evidence.label,
            )
        }
        val selected = classified.filter { it.kind != FieldKind.UNKNOWN }.toMutableList()
        if (manualRequest && selected.none { it.focused }) {
            classified.firstOrNull { it.focused }?.let {
                selected.add(0, it)
            }
        }
        return selected
            .distinctBy { it.id }
            .sortedWith(compareByDescending<ClassifiedField<T>> { it.focused }.thenByDescending { it.score })
            .take(MAX_FIELDS)
    }

    private fun hintKind(raw: String): FieldKind? = when (normalize(raw)) {
        "username", "userid", "login", "account" -> FieldKind.USERNAME
        "email", "emailaddress" -> FieldKind.EMAIL
        "password", "currentpassword" -> FieldKind.PASSWORD
        "newpassword" -> FieldKind.NEW_PASSWORD
        "smsotpcode", "onetimecode", "one-time-code", "otp", "emailotpcode", "2faappotpcode",
        "totp", "2fa", "twofactor" -> FieldKind.OTP
        "name", "fullname", "personname" -> FieldKind.FULL_NAME
        "phone", "phonenumber", "tel", "telephonenumber" -> FieldKind.PHONE
        "country", "countryname", "countrycode" -> FieldKind.COUNTRY
        "region", "state", "addressregion" -> FieldKind.REGION
        "city", "addresslocality" -> FieldKind.CITY
        "streetaddress", "addressline1", "postaladdress" -> FieldKind.STREET_ADDRESS
        "postalcode", "zipcode", "zip" -> FieldKind.POSTAL_CODE
        "creditcardholdername", "ccholdername" -> FieldKind.CARDHOLDER
        "creditcardnumber", "ccnumber" -> FieldKind.CARD_NUMBER
        "creditcardexpirationdate", "ccexp", "ccexpiration" -> FieldKind.CARD_EXPIRY
        "creditcardsecuritycode", "cccvv", "cvv", "cvc" -> FieldKind.CARD_CVV
        "idnumber", "identitynumber", "documentnumber" -> FieldKind.ID_NUMBER
        "apikey", "accesstoken" -> FieldKind.API_KEY
        "apisecret", "clientsecret" -> FieldKind.API_SECRET
        "host", "hostname", "serverhost" -> FieldKind.HOST
        "port", "serverport" -> FieldKind.PORT
        "database", "databasename", "dbname" -> FieldKind.DATABASE
        "ssid", "wifissid", "networkname" -> FieldKind.SSID
        "wifipassword", "networkpassword" -> FieldKind.WIFI_PASSWORD
        "recoveryanswer", "securityanswer" -> FieldKind.RECOVERY_ANSWER
        "customtext" -> FieldKind.CUSTOM_TEXT
        "customsecret" -> FieldKind.CUSTOM_SECRET
        else -> null
    }

    private fun tokenKind(raw: String?): FieldKind? {
        val value = normalize(raw ?: return null)
        return when {
            value.contains("wifipassword") || value.contains("networkpassword") || value.contains("wifi\u5bc6\u7801") -> FieldKind.WIFI_PASSWORD
            value.contains("apisecret") || value.contains("clientsecret") || value.contains("api\u5bc6\u6587") -> FieldKind.API_SECRET
            value.contains("customsecret") || value.contains("\u81ea\u5b9a\u4e49\u5bc6\u6587") -> FieldKind.CUSTOM_SECRET
            value.contains("recoveryanswer") || value.contains("securityanswer") || value.contains("\u6062\u590d\u7b54\u6848") || value.contains("\u5b89\u5168\u95ee\u9898\u7b54\u6848") -> FieldKind.RECOVERY_ANSWER
            value.contains("newpassword") || value.contains("confirmpassword") ||
                value.contains("新密码") || value.contains("确认密码") -> FieldKind.NEW_PASSWORD
            value.contains("password") || value.contains("passwd") || value.contains("pwd") ||
                value.contains("密码") -> FieldKind.PASSWORD
            value.contains("email") || value.contains("邮箱") || value.contains("邮件") -> FieldKind.EMAIL
            value.contains("username") || value.contains("userid") || value.contains("account") ||
                value.contains("loginname") || value.contains("用户名") || value.contains("账号") ||
                value.contains("帐号") -> FieldKind.USERNAME
            value.contains("otp") || value.contains("totp") || value.contains("2fa") ||
                value.contains("verificationcode") || value.contains("验证码") -> FieldKind.OTP
            value.contains("postalcode") || value.contains("zipcode") || value == "zip" || value.contains("\u90ae\u7f16") -> FieldKind.POSTAL_CODE
            value.contains("phone") || value.contains("telephone") || value.contains("\u624b\u673a\u53f7") || value.contains("\u7535\u8bdd") -> FieldKind.PHONE
            value.contains("fullname") || value.contains("realname") || value.contains("\u59d3\u540d") -> FieldKind.FULL_NAME
            value.contains("cardnumber") || value.contains("\u94f6\u884c\u5361\u53f7") || value == "\u5361\u53f7" -> FieldKind.CARD_NUMBER
            value.contains("cardholder") || value.contains("\u6301\u5361\u4eba") -> FieldKind.CARDHOLDER
            value.contains("cardexpiry") || value.contains("ccexp") || value.contains("\u5361\u7247\u6709\u6548\u671f") -> FieldKind.CARD_EXPIRY
            value.contains("cvv") || value.contains("cvc") || value.contains("\u5b89\u5168\u7801") -> FieldKind.CARD_CVV
            value.contains("idnumber") || value.contains("identitynumber") || value.contains("\u8bc1\u4ef6\u53f7") || value.contains("\u8eab\u4efd\u8bc1\u53f7") -> FieldKind.ID_NUMBER
            value.contains("apikey") || value.contains("accesstoken") || value.contains("api\u5bc6\u94a5") || value.contains("api\u51ed\u8bc1") -> FieldKind.API_KEY
            value.contains("serverhost") || value == "host" || value.contains("hostname") || value == "\u4e3b\u673a" -> FieldKind.HOST
            value.contains("serverport") || value == "port" || value == "\u7aef\u53e3" -> FieldKind.PORT
            value.contains("databasename") || value == "database" || value.contains("dbname") || value.contains("\u6570\u636e\u5e93\u540d") -> FieldKind.DATABASE
            value.contains("wifissid") || value == "ssid" || value.contains("\u7f51\u7edc\u540d\u79f0") -> FieldKind.SSID
            value.contains("customtext") || value.contains("\u81ea\u5b9a\u4e49\u6587\u672c") -> FieldKind.CUSTOM_TEXT
            value.contains("streetaddress") || value.contains("addressline") || value.contains("\u8be6\u7ec6\u5730\u5740") -> FieldKind.STREET_ADDRESS
            value.contains("city") || value.contains("\u57ce\u5e02") -> FieldKind.CITY
            value.contains("state") || value.contains("province") || value.contains("\u7701\u4efd") -> FieldKind.REGION
            value.contains("country") || value.contains("\u56fd\u5bb6") -> FieldKind.COUNTRY
            else -> null
        }
    }

    private fun normalize(value: String): String =
        value.lowercase().replace(Regex("[^a-z0-9\\u4e00-\\u9fff]"), "")

    private fun FieldKind.isSpecialized(): Boolean = this in setOf(
        FieldKind.ID_NUMBER, FieldKind.API_KEY, FieldKind.API_SECRET, FieldKind.HOST, FieldKind.PORT,
        FieldKind.DATABASE, FieldKind.SSID, FieldKind.WIFI_PASSWORD, FieldKind.RECOVERY_ANSWER,
        FieldKind.CUSTOM_TEXT, FieldKind.CUSTOM_SECRET,
    )
}
