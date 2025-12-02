package com.zerosms.testing.core.qualcomm

import android.util.Log
import com.zerosms.testing.core.root.RootAccessManager
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * Manages Qualcomm-specific diagnostic port enablement.
 * Certain Snapdragon devices require USB configuration changes to expose /dev/smd* and diag ports.
 */
object QualcommDiagManager {
    private const val TAG = "QualcommDiagManager"

    private val diagProperties = listOf(
        "persist.vendor.usb.config",
        "persist.sys.usb.config",
        "sys.usb.config"
    )

    private val defaultVariants = listOf(
        "diag,serial_cdev,rmnet,dpl,qdss,adb",
        "diag,diag_mdm,adb",
        "diag,adb"
    )

    private val presetProfiles = listOf(
        QualcommDiagProfile(
            id = "generic",
            label = "Generic Snapdragon (diag + serial_cdev)",
            description = "Works on most Qualcomm/Pixel devices",
            variants = listOf("diag,serial_cdev,rmnet,dpl,qdss,adb", "diag,serial_cdev,rmnet,adb")
        ),
        QualcommDiagProfile(
            id = "inseego-m2000",
            label = "Inseego MiFi M2000/M2100 (diag_mdm)",
            description = "Preferred on Inseego / Novatel MiFi units",
            variants = listOf("diag,diag_mdm,adb")
        ),
        QualcommDiagProfile(
            id = "inseego-8000",
            label = "Inseego 5G MiFi 8000 (serial_cdev minimal)",
            description = "Use when rmnet/dpl modes fail",
            variants = listOf("diag,serial_cdev,adb", "diag,adb")
        )
    )

    fun getPresetProfiles(): List<QualcommDiagProfile> = presetProfiles

    /**
     * Enables Qualcomm diagnostic USB ports by updating USB config system properties.
     */
    suspend fun enableDiagnosticPorts(profile: QualcommDiagProfile? = null): QualcommDiagResult = withContext(Dispatchers.IO) {
        val details = mutableListOf<String>()
        var success = false
        var appliedProp: String? = null
        var appliedVariant: String? = null

        val variants = profile?.variants ?: defaultVariants

        for (prop in diagProperties) {
            for (variant in variants) {
                val command = "setprop $prop $variant"
                val result = RootAccessManager.executeRootCommand(command)
                details.add("$command -> exit=${result.exitCode}")
                if (result.success && !success) {
                    success = true
                    appliedProp = prop
                    appliedVariant = variant
                }
            }
        }

        val activeConfig = getActiveUsbConfigInternal()
        val message = when {
            success && profile != null -> "Applied ${profile.label}. sys.usb.config=$activeConfig"
            success -> "Applied diagnostic USB config ($appliedProp=$appliedVariant). sys.usb.config=$activeConfig"
            else -> "Failed to update diagnostic USB config (sys.usb.config=$activeConfig)"
        }

        Log.d(TAG, "enableDiagnosticPorts success=$success activeConfig=$activeConfig")
        QualcommDiagResult(success, message, activeConfig, details, profile?.id)
    }

    /**
     * Returns the currently active USB configuration prop responsible for diag ports.
     */
    suspend fun getActiveUsbConfig(): String? = withContext(Dispatchers.IO) {
        getActiveUsbConfigInternal()
    }

    private suspend fun getActiveUsbConfigInternal(): String? {
        RootAccessManager.getSystemProperty("sys.usb.config")?.let {
            if (it.isNotEmpty()) return it
        }
        RootAccessManager.getSystemProperty("persist.sys.usb.config")?.let {
            if (it.isNotEmpty()) return it
        }
        return RootAccessManager.getSystemProperty("persist.vendor.usb.config")
    }
}

data class QualcommDiagProfile(
    val id: String,
    val label: String,
    val description: String,
    val variants: List<String>
)

data class QualcommDiagResult(
    val success: Boolean,
    val message: String,
    val activeConfig: String?,
    val details: List<String>,
    val profileId: String?
)
