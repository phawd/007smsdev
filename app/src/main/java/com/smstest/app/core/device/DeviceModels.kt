package com.smstest.app.core.device

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

data class ModemInfo(
    val chipset: ModemChipset,
    val radioType: RadioType,
    val modemDevicePaths: List<String>,
    val atCommandMethod: AtCommandMethod,
    val supportsDirectModemAccess: Boolean
)

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

enum class RadioType(val displayName: String) {
    GSM("GSM/UMTS/HSPA"),
    CDMA("CDMA/EVDO"),
    LTE("LTE (4G)"),
    NR_5G("5G NR"),
    UNKNOWN("Unknown")
}

enum class AtCommandMethod(val displayName: String) {
    QCRIL_SMD("Qualcomm SMD"),
    MEDIATEK_CCCI("MediaTek CCCI"),
    SAMSUNG_IPC("Samsung IPC"),
    HUAWEI_APPVCOM("Huawei APPVCOM"),
    INTEL_TTY("Intel TTY"),
    SPREADTRUM_STTY("Spreadtrum STTY"),
    STANDARD_TTY("Standard TTY/USB"),
    UNKNOWN("Unknown")
}

enum class SmsStrategy(val displayName: String) {
    AT_COMMANDS_PRIMARY("AT Commands (Primary)"),
    AT_WITH_FALLBACK("AT with Fallback"),
    STANDARD_API_ONLY("Standard API Only")
}
