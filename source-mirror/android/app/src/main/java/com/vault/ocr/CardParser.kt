package com.vault.ocr

/**
 * 银行卡 / 证件文本解析。与桌面端 core/ocr.py 的正则规则保持一致，
 * 解析结果以 Map<String,String> 返回，键名与桌面端字段对齐：
 *  - credit_card: card_number / card_number_last4 / expiry / cvv / cardholder / bank
 *  - id_card: id_number / id_type / full_name / ethnicity / address / issuing_authority /
 *             issue_date / expiry_date / birth_date / gender
 */
object CardParser {

    /** OCR 文本输入上限：超出截断，防止恶意/损坏图片产出超长文本拖死正则。 */
    private const val MAX_INPUT_LEN = 16 * 1024
    /** 自由文本字段（地址、签发机关）输出上限。 */
    private const val MAX_FREE_TEXT_LEN = 80

    private fun String.capInput(): String =
        if (length > MAX_INPUT_LEN) substring(0, MAX_INPUT_LEN) else this

    private fun String.capField(): String =
        trim().let { if (it.length > MAX_FREE_TEXT_LEN) it.substring(0, MAX_FREE_TEXT_LEN) else it }

    // ---- 银行卡 ----
    private val DIGIT_FIX = mapOf(
        'O' to '0', 'o' to '0', 'I' to '1', 'i' to '1', 'L' to '1', 'l' to '1',
        'S' to '5', 's' to '5', 'B' to '8', 'b' to '8',
    )

    private fun cleanCardNumber(raw: String): String =
        raw.replace(Regex("[\\s\\-]"), "").map { DIGIT_FIX[it] ?: it }.joinToString("")

    private fun looksLikeCardNumber(raw: String): Boolean {
        val digits = cleanCardNumber(raw)
        if (digits.length !in 13..19) return false
        val rawNoSep = raw.replace(Regex("[\\s\\-]"), "")
        val digitCount = rawNoSep.count { it.isDigit() }
        return digitCount * 2 >= rawNoSep.length
    }

    private fun luhnValid(digits: String): Boolean {
        if (digits.any { !it.isDigit() }) return false
        var total = 0
        for ((i, ch) in digits.reversed().withIndex()) {
            var d = ch.digitToInt()
            if (i % 2 == 1) { d *= 2; if (d > 9) d -= 9 }
            total += d
        }
        return total % 10 == 0
    }

    private val RE_CARD =
        Regex("([0-9OoIiLlSsBb]{2,19}(?:[\\s\\-][0-9OoIiLlSsBb]{2,19}){0,4})")
    private val RE_EXPIRY = Regex("(0?[1-9]|1[0-2])[/\\-](\\d{2}|\\d{4})")
    private val RE_NAME_EN = Regex("([A-Z][A-Z\\s]{2,24})")
    private val RE_CVV_BLOCK = Regex("([0-9OoIiLlSsBb]{7})")
    private val RE_CVV_LABEL = Regex("(?:CVV2?|安全码)\\s*[:：]?\\s*([0-9OoIiLlSsBb]{3,4})", RegexOption.IGNORE_CASE)
    private val RE_CVV_STANDALONE = Regex("^([0-9OoIiLlSsBb]{3})$")
    private val RE_BANK_CN = Regex("([一-鿿]{2,12}银行)")

    private val CARD_SKIP = setOf(
        "VISA", "MASTERCARD", "UNIONPAY", "AMEX", "DEBIT", "CREDIT", "BANK", "CARD",
        "CHINA", "CONSTRUCTION", "INDUSTRIAL", "COMMERCIAL", "COMMUNICATIONS",
        "AGRICULTURAL", "AGRICULTURE", "MERCHANTS", "MERCHANT", "EVERBRIGHT",
        "CITIC", "MINSHENG", "HUAXIA", "HUA", "XIA", "GUANGFA", "PUDONG",
        "DEVELOPMENT", "SHANGHAI", "POSTAL", "SAVINGS", "PING", "AN", "OF", "AND",
        "THE", "NATIONAL", "LIMITED", "LTD", "CO", "CORPORATION", "GROUP",
        "INTERNATIONAL", "ICBC", "CCB", "ABC", "BOC", "BOCOM", "CEB", "CMB", "CGB",
        "HSBC", "CITIBANK", "CITI", "CHASE", "PREMIER", "ELITE", "WORLD",
        "PLATINUM", "GOLD", "SIGNATURE", "INFINITE",
    )

    private val BANK_ABBR = mapOf(
        "ICBC" to "中国工商银行", "CCB" to "中国建设银行", "ABC" to "中国农业银行",
        "BOCOM" to "交通银行", "BOC" to "中国银行", "CMB" to "招商银行",
        "SPDB" to "浦发银行", "CIB" to "兴业银行", "CEB" to "中国光大银行",
        "CGB" to "广发银行", "PSBC" to "中国邮政储蓄银行",
    )

    fun parseCreditCard(rawText: String): Map<String, String> {
        val text = rawText.capInput()
        val result = mutableMapOf<String, String>()
        val lines = text.lines().map { it.trim() }.filter { it.isNotEmpty() }

        // 卡号：候选组合，优先「完整覆盖整段」+ Luhn 校验，其次最长
        var best: String? = null
        var bestLuhn = false
        var bestFull = false
        for (m in RE_CARD.findAll(text)) {
            val tokens = m.groupValues[1].split(Regex("[\\s\\-]+"))
            for (i in tokens.indices) for (j in (i + 1)..tokens.size) {
                val candidate = tokens.subList(i, j).joinToString("")
                if (!looksLikeCardNumber(candidate)) continue
                val full = (i == 0 && j == tokens.size)
                val luhn = luhnValid(cleanCardNumber(candidate))
                val pickedBetter = when {
                    best == null -> true
                    full && !bestFull -> true
                    full != bestFull -> false
                    luhn && !bestLuhn -> true
                    luhn == bestLuhn && candidate.length > (best?.length ?: 0) -> true
                    else -> false
                }
                if (pickedBetter) { best = candidate; bestLuhn = luhn; bestFull = full }
            }
        }
        if (best != null) {
            val digits = cleanCardNumber(best!!)
            result["card_number"] = digits
            result["card_number_last4"] = digits.takeLast(4)
            for (m in RE_CVV_BLOCK.findAll(text)) {
                val block = cleanCardNumber(m.groupValues[1])
                if (block.take(4) == result["card_number_last4"]) {
                    result["cvv"] = block.takeLast(3); break
                }
            }
        }
        if ("cvv" !in result) {
            RE_CVV_LABEL.find(text)?.let {
                result["cvv"] = cleanCardNumber(it.groupValues[1]).takeLast(3)
            }
        }
        if ("cvv" !in result) {
            for (line in lines) {
                RE_CVV_STANDALONE.matchEntire(line)?.let {
                    result["cvv"] = cleanCardNumber(it.groupValues[1])
                    return@let
                }
                if ("cvv" in result) break
            }
        }

        RE_EXPIRY.find(text)?.let {
            val month = it.groupValues[1].padStart(2, '0')
            val year = it.groupValues[2].takeLast(2)
            result["expiry"] = "$month/$year"
        }

        for (line in lines) {
            RE_NAME_EN.find(line)?.let {
                val candidate = it.groupValues[1].trim()
                val words = candidate.split(Regex("\\s+"))
                if (words.size in 2..4 && words.none { w -> w in CARD_SKIP }) {
                    result["cardholder"] = candidate
                    return@let
                }
            }
            if ("cardholder" in result) break
        }

        val bankMatches = RE_BANK_CN.findAll(text).map { it.groupValues[1] }.toList()
        if (bankMatches.isNotEmpty()) {
            val counts = bankMatches.groupingBy { it }.eachCount()
            val maxCount = counts.values.max()
            result["bank"] = bankMatches.first { counts[it] == maxCount }
        } else {
            val up = text.uppercase()
            for ((abbr, full) in BANK_ABBR) {
                if (Regex("\\b$abbr\\b").containsMatchIn(up)) {
                    result["bank"] = full; break
                }
            }
        }
        return result
    }

    // ---- 证件 ----
    private val RE_ID_CN = Regex(
        "([1-9]\\d{5}(?:18|19|20)\\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\\d|3[01])\\d{3}[\\dXx])"
    )
    private val RE_PASSPORT_CN = Regex("([GEDged]\\d{8})")
    private val RE_DATE = Regex(
        "(\\d{4})[.年\\-/](\\d{1,2})[.月\\-/](\\d{1,2})日?" +
            "|(?<!\\d)(\\d{8})(?!\\d)"
    )
    private val RE_HAN = Regex("[一-鿿]")
    private val LABEL_WORDS = setOf("姓名", "性别", "民族", "出生", "住址", "签发", "有效", "公民", "身份")
    private val NAME_BLOCKLIST = setOf(
        "中华人民", "人民共和", "共和国", "共和国居", "民共和国",
        "居民身份", "身份证", "中华人民共和国",
    )

    private fun fmtDate(m: MatchResult): String {
        val g4 = m.groups[4]?.value
        if (g4 != null) return "${g4.substring(0,4)}-${g4.substring(4,6)}-${g4.substring(6,8)}"
        val y = m.groupValues[1]
        val mo = m.groupValues[2].padStart(2, '0')
        val d = m.groupValues[3].padStart(2, '0')
        return "$y-$mo-$d"
    }

    fun parseIdCard(rawText: String): Map<String, String> {
        val text = rawText.capInput()
        val result = mutableMapOf<String, String>()
        val lines = text.lines().map { it.trim() }.filter { it.isNotEmpty() }

        RE_ID_CN.find(text)?.let {
            val num = it.groupValues[1].uppercase()
            result["id_number"] = num
            result["id_type"] = "身份证"
            result["birth_date"] = "${num.substring(6,10)}-${num.substring(10,12)}-${num.substring(12,14)}"
            result["gender"] = if (num[16].digitToInt() % 2 == 1) "男" else "女"
        } ?: run {
            RE_PASSPORT_CN.find(text)?.let {
                result["id_number"] = it.groupValues[1].uppercase()
                result["id_type"] = "护照"
            }
        }

        Regex("姓\\s*名\\s*[:：]?\\s*([一-鿿]{2,6})").find(text)?.let {
            result["full_name"] = it.groupValues[1]
        } ?: if (result.containsKey("id_type")) {
            for (line in lines) {
                val chars = RE_HAN.findAll(line).map { it.value }.toList()
                val joined = chars.joinToString("")
                if (chars.size in 2..4 &&
                    line !in LABEL_WORDS &&
                    "族" !in line &&
                    joined !in NAME_BLOCKLIST
                ) {
                    result["full_name"] = joined; break
                }
            }
        } else Unit

        Regex("民\\s*族\\s*[:：]?\\s*([一-鿿]{1,4})").find(text)?.let {
            result["ethnicity"] = it.groupValues[1]
        }
        Regex("(?:住址|地址)\\s*[:：]?\\s*(.+)").find(text)?.let {
            result["address"] = it.groupValues[1].capField()
        }
        for (line in lines) {
            if (listOf("公安局", "派出所", "公安分局").any { it in line }) {
                result["issuing_authority"] = line.replace(Regex("^签发机关\\s*[:：]?\\s*"), "").capField()
                break
            }
        }
        if ("issuing_authority" !in result) {
            Regex("签发机关\\s*[:：]?\\s*(.+)").find(text)?.let {
                result["issuing_authority"] = it.groupValues[1].capField()
            }
        }
        val span = when {
            Regex("有效期限?\\s*[:：]?\\s*(.+)").find(text) != null ->
                Regex("有效期限?\\s*[:：]?\\s*(.+)").find(text)!!.groupValues[1]
            result["id_type"] == "身份证" -> ""
            else -> text
        }
        val dates = RE_DATE.findAll(span).map { fmtDate(it) }.toList()
        if (dates.size >= 2) {
            result["issue_date"] = dates[0]
            result["expiry_date"] = dates[1]
        } else if (dates.size == 1) {
            result["issue_date"] = dates[0]
        }
        return result
    }
}
