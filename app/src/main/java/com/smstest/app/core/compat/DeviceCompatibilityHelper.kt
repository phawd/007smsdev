package com.smstest.app.core.compat

import android.os.Build
import com.smstest.app.core.device.ModemChipset

/**
 * Device-specific compatibility configuration for SMS/MMS delivery.
 *
 * Different chipsets and Android API levels require different strategies
 * for reliable SMS/MMS delivery.  This class centralises those decisions
 * so that callers do not need to scatter `Build.*` checks throughout the
 * codebase.
 */
object DeviceCompatibilityHelper {

    /**
     * Whether the device supports AT-command direct modem access.
     *
     * True only for Qualcomm-based devices where SMD character devices are
     * typically present, and only when the app has root / HIDL access.
     */
    fun supportsDirectAtAccess(chipset: ModemChipset): Boolean =
        chipset.name.startsWith("QUALCOMM") ||
        chipset.name.startsWith("MEDIATEK")

    /**
     * Recommended maximum SMS part size for the given chipset.
     *
     * Some older MediaTek firmware has issues with the standard 153-character
     * GSM 7-bit concatenated SMS header, so we use a slightly smaller value.
     */
    fun maxSmsPartLength(chipset: ModemChipset, isUnicode: Boolean): Int {
        val isMediaTek = chipset.name.startsWith("MEDIATEK")
        return when {
            isUnicode && isMediaTek -> 65   // conservative for MTK UCS-2
            isUnicode               -> 67
            isMediaTek              -> 152  // conservative for MTK GSM-7
            else                    -> 153
        }
    }

    /**
     * Returns true if the current Android API level requires the new
     * [android.telephony.SmsManager] retrieval path
     * (`context.getSystemService(SmsManager::class.java)` vs the deprecated
     * static `SmsManager.getDefault()`).
     */
    fun requiresContextSmsManager(): Boolean = Build.VERSION.SDK_INT >= Build.VERSION_CODES.S

    /**
     * Returns true if the device needs a manual network-type change before
     * MMS can be sent (observed on some Qualcomm devices running Android 9–11).
     */
    fun requiresMmsNetworkWorkaround(chipset: ModemChipset): Boolean {
        val sdkInt = Build.VERSION.SDK_INT
        val isQualcomm = chipset.name.startsWith("QUALCOMM")
        return isQualcomm && sdkInt in Build.VERSION_CODES.P..Build.VERSION_CODES.R
    }

    /**
     * Display-friendly summary of the compatibility profile for the given chipset.
     */
    fun compatibilitySummary(chipset: ModemChipset): String {
        val sb = StringBuilder()
        sb.appendLine("Chipset          : ${chipset.displayName}")
        sb.appendLine("SDK              : ${Build.VERSION.SDK_INT} (Android ${Build.VERSION.RELEASE})")
        sb.appendLine("AT access        : ${supportsDirectAtAccess(chipset)}")
        sb.appendLine("MMS workaround   : ${requiresMmsNetworkWorkaround(chipset)}")
        sb.appendLine("Context SMS API  : ${requiresContextSmsManager()}")
        return sb.toString().trimEnd()
    }
}
