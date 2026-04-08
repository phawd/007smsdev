package com.smstest.app.core.device

import android.content.Context
import android.os.Build
import android.telephony.TelephonyManager
import android.util.Log
import com.smstest.app.core.at.AtCapabilityScanResult
import com.smstest.app.core.at.AtCommandManager
import com.smstest.app.core.root.RootAccessManager
import com.smstest.app.core.root.RootActivityType
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import java.io.File

object DeviceInfoManager {
    private const val TAG = "DeviceInfoManager"

    private val _deviceInfo = MutableStateFlow<DeviceInfo?>(null)
    val deviceInfo: StateFlow<DeviceInfo?> = _deviceInfo.asStateFlow()

    private val _modemInfo = MutableStateFlow<ModemInfo?>(null)
    val modemInfo: StateFlow<ModemInfo?> = _modemInfo.asStateFlow()

    private val _detectionProgress = MutableStateFlow<List<String>>(emptyList())
    val detectionProgress: StateFlow<List<String>> = _detectionProgress.asStateFlow()

    private val _atCapabilityResults = MutableStateFlow<List<AtCapabilityScanResult>>(emptyList())
    val atCapabilityResults: StateFlow<List<AtCapabilityScanResult>> = _atCapabilityResults.asStateFlow()

    private val _isDetecting = MutableStateFlow(false)
    val isDetecting: StateFlow<Boolean> = _isDetecting.asStateFlow()

    private val detectionMutex = Mutex()

    suspend fun initialize(context: Context) = runDetection(context, force = false)
    suspend fun refresh(context: Context) = runDetection(context, force = true)

    fun cancelDetection() {
        _isDetecting.value = false
        appendProgress("✋ Detection cancelled by user")
        RootAccessManager.logActivity("Detection cancelled by user", RootActivityType.WARNING)
    }

    private suspend fun runDetection(context: Context, force: Boolean) {
        detectionMutex.withLock {
            if (_isDetecting.value) return
            if (!force && _deviceInfo.value != null && _modemInfo.value != null) return
            _isDetecting.value = true
            _detectionProgress.value = emptyList()
            _atCapabilityResults.value = emptyList()
        }

        try {
            appendProgress("🚀 Starting device detection...")
            RootAccessManager.logActivity("Starting device detection...", RootActivityType.INFO)

            val info = detectDeviceInfo(context)
            _deviceInfo.value = info
            appendProgress("📱 Device: ${info.manufacturer} ${info.model}")
            appendProgress("📱 Android: ${info.androidVersion} (SDK ${info.sdkInt})")

            val modem = detectModemInfo(context)
            _modemInfo.value = modem
            appendProgress("📡 Chipset: ${modem.chipset.displayName}")
            appendProgress("📶 Radio: ${modem.radioType.displayName}")
            appendProgress("🔌 AT Method: ${modem.atCommandMethod.displayName}")

            val existingPaths = modem.modemDevicePaths.filter { File(it).exists() }
            appendProgress("📂 Modem paths found: ${existingPaths.size}")

            appendProgress("🔎 Probing AT capability...")
            val atScan = AtCommandManager.scanCapabilities(modem.modemDevicePaths)
            _atCapabilityResults.value = atScan
            appendProgress("📡 AT responsive: ${atScan.count { it.responded }}/${atScan.size}")

            val strategy = getRecommendedSmsStrategy()
            appendProgress("🎯 Strategy: ${strategy.displayName}")
            appendProgress("✔ Detection complete")
            RootAccessManager.logActivity(
                "Detection complete. Chipset: ${modem.chipset.displayName}, Strategy: ${strategy.displayName}",
                RootActivityType.SUCCESS
            )
        } catch (e: Exception) {
            Log.e(TAG, "Device detection failed", e)
            appendProgress("❌ Detection failed: ${e.message}")
            RootAccessManager.logActivity("Detection failed: ${e.message}", RootActivityType.ERROR)
        } finally {
            _isDetecting.value = false
        }
    }

    private suspend fun detectDeviceInfo(context: Context): DeviceInfo = withContext(Dispatchers.IO) {
        DeviceInfo(
            manufacturer = Build.MANUFACTURER,
            model = Build.MODEL,
            brand = Build.BRAND,
            device = Build.DEVICE,
            hardware = Build.HARDWARE,
            board = Build.BOARD,
            androidVersion = Build.VERSION.RELEASE,
            sdkInt = Build.VERSION.SDK_INT,
            basebandVersion = Build.getRadioVersion() ?: "Unknown"
        )
    }

    private suspend fun detectModemInfo(context: Context): ModemInfo = withContext(Dispatchers.IO) {
        val telephonyManager = context.getSystemService(Context.TELEPHONY_SERVICE) as TelephonyManager
        val chipset = detectChipset()
        val radio = detectRadioType(telephonyManager)
        val paths = getModemPaths(chipset)
        val method = detectAtCommandMethod(chipset)
        ModemInfo(
            chipset = chipset,
            radioType = radio,
            modemDevicePaths = paths,
            atCommandMethod = method,
            supportsDirectModemAccess = chipset != ModemChipset.UNKNOWN
        )
    }

    private fun detectChipset(): ModemChipset {
        val combined = "${Build.HARDWARE} ${Build.BOARD} ${Build.DEVICE}".lowercase()
        return when {
            combined.contains("qcom") || combined.contains("msm") || combined.contains("sdm") || combined.contains("snapdragon") -> ModemChipset.QUALCOMM_SDM
            combined.contains("mt") || combined.contains("mediatek") -> ModemChipset.MEDIATEK_GENERIC
            combined.contains("exynos") -> ModemChipset.SAMSUNG_EXYNOS
            combined.contains("kirin") || combined.contains("hi36") -> ModemChipset.HISILICON_KIRIN
            combined.contains("intel") || combined.contains("ifx") -> ModemChipset.INTEL_XMM
            combined.contains("spreadtrum") || combined.contains("unisoc") -> ModemChipset.SPREADTRUM
            else -> ModemChipset.UNKNOWN
        }
    }

    private fun detectRadioType(telephonyManager: TelephonyManager): RadioType {
        return try {
            when (telephonyManager.dataNetworkType) {
                TelephonyManager.NETWORK_TYPE_NR -> RadioType.NR_5G
                TelephonyManager.NETWORK_TYPE_LTE -> RadioType.LTE
                TelephonyManager.NETWORK_TYPE_CDMA,
                TelephonyManager.NETWORK_TYPE_EVDO_0,
                TelephonyManager.NETWORK_TYPE_EVDO_A,
                TelephonyManager.NETWORK_TYPE_EVDO_B,
                TelephonyManager.NETWORK_TYPE_1xRTT -> RadioType.CDMA
                else -> RadioType.GSM
            }
        } catch (_: Exception) {
            RadioType.UNKNOWN
        }
    }

    private fun getModemPaths(chipset: ModemChipset): List<String> = when (chipset) {
        ModemChipset.QUALCOMM_GENERIC, ModemChipset.QUALCOMM_MSM7XXX, ModemChipset.QUALCOMM_MSM8XXX, ModemChipset.QUALCOMM_SDM ->
            listOf("/dev/smd0", "/dev/smd11", "/dev/ttyHS0", "/dev/ttyUSB0", "/dev/ttyUSB1", "/dev/wwan0at")
        ModemChipset.MEDIATEK_GENERIC, ModemChipset.MEDIATEK_HELIO, ModemChipset.MEDIATEK_DIMENSITY ->
            listOf("/dev/radio/pttycmd1", "/dev/ttyMT0", "/dev/ttyCMIPC0")
        ModemChipset.SAMSUNG_EXYNOS -> listOf("/dev/umts_ipc0", "/dev/modem_ctl")
        ModemChipset.HISILICON_KIRIN -> listOf("/dev/appvcom", "/dev/ttyUSB0")
        ModemChipset.INTEL_XMM -> listOf("/dev/gsmtty1", "/dev/ttyIFX0")
        ModemChipset.SPREADTRUM -> listOf("/dev/stty_lte1", "/dev/stty_lte2")
        ModemChipset.UNKNOWN -> listOf("/dev/smd0", "/dev/smd11", "/dev/ttyUSB0", "/dev/ttyUSB1", "/dev/ttyACM0")
    }

    private fun detectAtCommandMethod(chipset: ModemChipset): AtCommandMethod = when (chipset) {
        ModemChipset.QUALCOMM_GENERIC, ModemChipset.QUALCOMM_MSM7XXX, ModemChipset.QUALCOMM_MSM8XXX, ModemChipset.QUALCOMM_SDM -> AtCommandMethod.QCRIL_SMD
        ModemChipset.MEDIATEK_GENERIC, ModemChipset.MEDIATEK_HELIO, ModemChipset.MEDIATEK_DIMENSITY -> AtCommandMethod.MEDIATEK_CCCI
        ModemChipset.SAMSUNG_EXYNOS -> AtCommandMethod.SAMSUNG_IPC
        ModemChipset.HISILICON_KIRIN -> AtCommandMethod.HUAWEI_APPVCOM
        ModemChipset.INTEL_XMM -> AtCommandMethod.INTEL_TTY
        ModemChipset.SPREADTRUM -> AtCommandMethod.SPREADTRUM_STTY
        ModemChipset.UNKNOWN -> AtCommandMethod.STANDARD_TTY
    }

    fun getRecommendedSmsStrategy(): SmsStrategy {
        val modem = _modemInfo.value ?: return SmsStrategy.STANDARD_API_ONLY
        return when {
            RootAccessManager.rootAvailable.value == true && modem.supportsDirectModemAccess -> SmsStrategy.AT_COMMANDS_PRIMARY
            RootAccessManager.rootAvailable.value == true -> SmsStrategy.AT_WITH_FALLBACK
            else -> SmsStrategy.STANDARD_API_ONLY
        }
    }

    private fun appendProgress(line: String) {
        val updated = _detectionProgress.value + line
        _detectionProgress.value = updated.takeLast(50)
        Log.d(TAG, line)
    }
}
