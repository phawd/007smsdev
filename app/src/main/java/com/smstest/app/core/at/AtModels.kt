package com.smstest.app.core.at

import com.smstest.app.core.device.ModemChipset

data class AtCapabilityScanResult(
    val devicePath: String,
    val chipset: ModemChipset,
    val exists: Boolean,
    val accessible: Boolean,
    val responded: Boolean,
    val responseSnippet: String
)
