package com.smstest.app.core.device

/**
 * Device information
 */
data class DeviceInfo(
    val manufacturer: String,
    val model: String,
    val brand: String,
    val device: String,
    val hardware: String,
    val board: String,
    val androidVersion: String,
    val sdkInt: Int,
    val basebandVersion: String
)

/**
 * Modem information
 */
data class ModemInfo(
    val chipset: ModemChipset,
    val radioType: RadioType,
    val modemDevicePaths: List<String>,
    val atCommandMethod: AtCommandMethod,
    val supportsDirectModemAccess: Boolean
)

/**
 * Supported modem chipsets
 */
enum class ModemChipset(val displayName: String) {
    QUALCOMM_GENERIC("Qualcomm Generic"),
    QUALCOMM_MSM7XXX("Qualcomm MSM7xxx"),
    QUALCOMM_MSM8XXX("Qualcomm MSM8xxx"),
    QUALCOMM_SDM("Qualcomm Snapdragon (SDM)"),
    MEDIATEK_GENERIC("MediaTek Generic"),
    MEDIATEK_HELIO("MediaTek Helio"),
    MEDIATEK_DIMENSITY("MediaTek Dimensity"),
    SAMSUNG_EXYNOS("Samsung Exynos"),
    HISILICON_KIRIN("HiSilicon Kirin"),
    INTEL_XMM("Intel XMM"),
    SPREADTRUM("Spreadtrum/UNISOC"),
    UNKNOWN("Unknown")
}

/**
 * Radio technology types
 */
enum class RadioType(val displayName: String) {
    GSM("GSM/UMTS/HSPA"),
    CDMA("CDMA/EVDO"),
    LTE("LTE (4G)"),
    NR_5G("5G NR"),
    UNKNOWN("Unknown")
}

/**
 * AT command communication methods
 */
enum class AtCommandMethod {
    QCRIL_SMD,          // Qualcomm SMD (Shared Memory Device)
    MEDIATEK_CCCI,      // MediaTek CCCI (Cross Core Communication Interface)
    SAMSUNG_IPC,        // Samsung IPC (Inter-Processor Communication)
    HUAWEI_APPVCOM,     // Huawei/HiSilicon APPVCOM
    INTEL_TTY,          // Intel modem TTY
    SPREADTRUM_STTY,    // Spreadtrum STTY
    STANDARD_TTY,       // Standard TTY/USB
    UNKNOWN             // Unknown/Generic
}

/**
 * SMS sending strategies
 */
enum class SmsStrategy {
    AT_COMMANDS_PRIMARY,    // Use AT commands as primary method
    AT_WITH_FALLBACK,       // Try AT commands, fallback to standard API
    STANDARD_API_ONLY       // Use only standard Android SMS API
}
