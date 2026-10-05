package com.vault.ui

/**
 * 标签文本统一规范化：按逗号（中英文）、空格、全角空格、制表符、换行切分，
 * trim、去空、去重并保持输入顺序。编辑页与批量"添加标签"共用同一解析规则。
 */
fun splitTagText(v: String): List<String> =
    v.split(",", "，", " ", "　", "\t", "\n")
        .map { it.trim() }
        .filter { it.isNotEmpty() }
        .distinct()