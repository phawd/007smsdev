package com.zerosms.testing.core.at

import com.zerosms.testing.core.device.ModemChipset

data class AtCapabilityScanResult(
    val devicePath: String,
    val chipset: ModemChipset,
    val exists: Boolean,
    val accessible: Boolean,
    val responded: Boolean,
    val responseSnippet: String
)
