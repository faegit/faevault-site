package com.vault.ui

import androidx.annotation.DrawableRes
import com.vault.R
import com.vault.model.ModuleType
import com.vault.model.SecretType

/** Single source of truth for category and module icon resources. */
internal object VaultIconResources {
    @DrawableRes
    fun category(type: String): Int = when (type) {
        SecretType.LOGIN -> R.drawable.ic_category_login
        SecretType.WIFI -> R.drawable.ic_category_wifi
        SecretType.CARD_DOCUMENT -> R.drawable.ic_category_card_document
        SecretType.API_KEY -> R.drawable.ic_category_api_key
        SecretType.OTP -> R.drawable.ic_category_otp
        SecretType.SECURE_NOTE -> R.drawable.ic_category_secure_note
        SecretType.SERVER -> R.drawable.ic_category_server
        SecretType.CUSTOM -> R.drawable.ic_category_custom
        SecretType.PASSKEY -> R.drawable.ic_category_passkey
        else -> R.drawable.ic_category_login
    }

    @DrawableRes
    fun module(type: String): Int = when (type) {
        ModuleType.TEXT -> R.drawable.ic_module_text
        ModuleType.PASSWORD -> R.drawable.ic_module_password
        ModuleType.MULTILINE -> R.drawable.ic_module_markdown
        ModuleType.BOOLEAN -> R.drawable.ic_module_boolean
        ModuleType.DATETIME -> R.drawable.ic_module_datetime
        ModuleType.IMAGES -> R.drawable.ic_module_images
        ModuleType.ATTACHMENTS -> R.drawable.ic_module_attachments
        ModuleType.LOGIN_ACCOUNT -> category(SecretType.LOGIN)
        ModuleType.TARGET_APP -> R.drawable.ic_module_target_app
        ModuleType.API_CREDENTIAL -> category(SecretType.API_KEY)
        ModuleType.WIFI -> category(SecretType.WIFI)
        ModuleType.SERVER_CONNECTION -> category(SecretType.SERVER)
        ModuleType.SSH -> R.drawable.ic_module_ssh
        ModuleType.DATABASE -> R.drawable.ic_module_database
        ModuleType.OTP -> category(SecretType.OTP)
        ModuleType.CARD_DOCUMENT -> category(SecretType.CARD_DOCUMENT)
        ModuleType.PASSKEY -> category(SecretType.PASSKEY)
        ModuleType.ADDRESS -> R.drawable.ic_module_address
        ModuleType.RECOVERY -> R.drawable.ic_module_recovery
        else -> R.drawable.ic_module_text
    }
}
