package com.smstest.app.core.at

import com.smstest.app.core.Logger

/**
 * Attempts to load an AtDeviceProvider implementation from a system property or env var.
 * Falls back to DefaultAtDeviceProvider on any failure.
 */
object AtDeviceProviderLoader {
    private const val SYS_PROP = "smstest.at.deviceProviderClass"
    private const val ENV_VAR = "SMSTEST_AT_DEVICE_PROVIDER_CLASS"

    fun loadProviderOrDefault(): AtDeviceProvider {
        val className = System.getProperty(SYS_PROP) ?: System.getenv(ENV_VAR)
        if (className.isNullOrBlank()) return DefaultAtDeviceProvider

        return try {
            val cls = Class.forName(className)
            val inst = cls.getDeclaredConstructor().newInstance()
            if (inst is AtDeviceProvider) {
                Logger.i("AtDeviceProviderLoader", "Loaded AtDeviceProvider: $className")
                inst
            } else {
                Logger.w("AtDeviceProviderLoader", "Class $className does not implement AtDeviceProvider")
                DefaultAtDeviceProvider
            }
        } catch (e: Exception) {
            Logger.w("AtDeviceProviderLoader", "Failed to load AtDeviceProvider $className: ${e.message}")
            DefaultAtDeviceProvider
        }
    }
}
