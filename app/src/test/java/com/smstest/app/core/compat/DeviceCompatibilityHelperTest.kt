package com.smstest.app.core.compat

import com.smstest.app.core.device.ModemChipset
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Unit tests for [DeviceCompatibilityHelper].
 *
 * These run on the JVM with Robolectric providing Android stubs, so they do
 * not require a physical device or emulator.
 */
class DeviceCompatibilityHelperTest {

    // --- supportsDirectAtAccess ---

    @Test
    fun `Qualcomm chipsets support direct AT access`() {
        assertTrue(DeviceCompatibilityHelper.supportsDirectAtAccess(ModemChipset.QUALCOMM_GENERIC))
        assertTrue(DeviceCompatibilityHelper.supportsDirectAtAccess(ModemChipset.QUALCOMM_MSM7XXX))
        assertTrue(DeviceCompatibilityHelper.supportsDirectAtAccess(ModemChipset.QUALCOMM_MSM8XXX))
        assertTrue(DeviceCompatibilityHelper.supportsDirectAtAccess(ModemChipset.QUALCOMM_SDM))
    }

    @Test
    fun `MediaTek chipsets support direct AT access`() {
        assertTrue(DeviceCompatibilityHelper.supportsDirectAtAccess(ModemChipset.MEDIATEK_GENERIC))
        assertTrue(DeviceCompatibilityHelper.supportsDirectAtAccess(ModemChipset.MEDIATEK_HELIO))
        assertTrue(DeviceCompatibilityHelper.supportsDirectAtAccess(ModemChipset.MEDIATEK_DIMENSITY))
    }

    @Test
    fun `Unknown chipset does not claim AT access`() {
        assertFalse(DeviceCompatibilityHelper.supportsDirectAtAccess(ModemChipset.UNKNOWN))
    }

    // --- maxSmsPartLength ---

    @Test
    fun `Standard GSM-7 part length is 153 for non-MediaTek`() {
        assertEquals(
            153,
            DeviceCompatibilityHelper.maxSmsPartLength(ModemChipset.QUALCOMM_GENERIC, isUnicode = false)
        )
    }

    @Test
    fun `MediaTek GSM-7 part length is 152 conservative`() {
        assertEquals(
            152,
            DeviceCompatibilityHelper.maxSmsPartLength(ModemChipset.MEDIATEK_HELIO, isUnicode = false)
        )
    }

    @Test
    fun `Standard UCS-2 part length is 67 for non-MediaTek`() {
        assertEquals(
            67,
            DeviceCompatibilityHelper.maxSmsPartLength(ModemChipset.SAMSUNG_EXYNOS, isUnicode = true)
        )
    }

    @Test
    fun `MediaTek UCS-2 part length is 65 conservative`() {
        assertEquals(
            65,
            DeviceCompatibilityHelper.maxSmsPartLength(ModemChipset.MEDIATEK_DIMENSITY, isUnicode = true)
        )
    }

    // --- compatibilitySummary ---

    @Test
    fun `compatibilitySummary contains chipset display name`() {
        val summary = DeviceCompatibilityHelper.compatibilitySummary(ModemChipset.QUALCOMM_SDM)
        assertTrue(summary.contains(ModemChipset.QUALCOMM_SDM.displayName))
    }

    @Test
    fun `compatibilitySummary contains SDK line`() {
        val summary = DeviceCompatibilityHelper.compatibilitySummary(ModemChipset.QUALCOMM_SDM)
        assertTrue(summary.contains("SDK"))
    }
}
