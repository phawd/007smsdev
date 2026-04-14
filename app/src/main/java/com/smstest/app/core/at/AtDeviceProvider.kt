package com.smstest.app.core.at

import com.smstest.app.core.device.ModemChipset

/**
 * Abstraction for providing candidate modem device paths.
 * Allows alternative implementations (different licenses) to be provided as plugins.
 */
interface AtDeviceProvider {
    fun getCandidateDeviceList(preferredPaths: List<String> = emptyList()): List<Pair<String, ModemChipset>>
}

object DefaultAtDeviceProvider : AtDeviceProvider {
    override fun getCandidateDeviceList(preferredPaths: List<String>): List<Pair<String, ModemChipset>> {
        val known = linkedMapOf<String, ModemChipset>()
        preferredPaths.forEach { known[it] = ModemChipset.UNKNOWN }
        val staticCandidates = mapOf(
            "/dev/smd0" to ModemChipset.QUALCOMM_GENERIC,
            "/dev/smd11" to ModemChipset.QUALCOMM_GENERIC,
            "/dev/ttyHS0" to ModemChipset.QUALCOMM_SDM,
            "/dev/ttyHS1" to ModemChipset.QUALCOMM_SDM,
            "/dev/ttyUSB0" to ModemChipset.UNKNOWN,
            "/dev/ttyUSB1" to ModemChipset.UNKNOWN,
            "/dev/ttyUSB2" to ModemChipset.UNKNOWN,
            "/dev/ttyACM0" to ModemChipset.UNKNOWN,
            "/dev/ttyACM1" to ModemChipset.UNKNOWN,
            "/dev/radio/pttycmd1" to ModemChipset.MEDIATEK_GENERIC,
            "/dev/radio/pttycmd2" to ModemChipset.MEDIATEK_GENERIC,
            "/dev/ttyMT0" to ModemChipset.MEDIATEK_GENERIC,
            "/dev/ttyCMIPC0" to ModemChipset.MEDIATEK_GENERIC,
            "/dev/umts_ipc0" to ModemChipset.SAMSUNG_EXYNOS,
            "/dev/appvcom" to ModemChipset.HISILICON_KIRIN,
            "/dev/gsmtty1" to ModemChipset.INTEL_XMM,
            "/dev/stty_lte1" to ModemChipset.SPREADTRUM,
            "/dev/wwan0at" to ModemChipset.QUALCOMM_SDM,
            "/dev/wwan1at" to ModemChipset.QUALCOMM_SDM
        )
        staticCandidates.forEach { (path, chipset) -> known.putIfAbsent(path, chipset) }
        return known.entries.map { it.key to it.value }
    }
}