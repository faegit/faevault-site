package com.vault.crypto

/**
 * 加密相关异常类型与错误分类，供 PMVE 主库（[PmvKeySchedule] / PmvVaultHeaderCodec /
 * PmvContainerFormat）、备份 v2（storage/PmvBackupCrypto）与上层（VaultRepository、
 * VaultViewModel、AutofillVaultGateway）复用的统一异常类型。
 *
 * - [DecryptError]：口令错误或载荷认证失败（tag 校验不过）。
 * - [CorruptFileError]：文件结构损坏（头不匹配 / 数据过短 / 版本或参数不支持）。
 */
object VaultCrypto {
    class DecryptError(message: String) : Exception(message)
    class CorruptFileError(message: String) : Exception(message)
}
