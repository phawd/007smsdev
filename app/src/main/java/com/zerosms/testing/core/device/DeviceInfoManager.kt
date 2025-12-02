package com.zerosms.testing.core.device

import android.content.Context
import android.os.Build
import android.telephony.TelephonyManager
import android.util.Log
import com.zerosms.testing.core.at.AtCapabilityScanResult
import com.zerosms.testing.core.at.AtCommandManager
import com.zerosms.testing.core.root.RootAccessManager
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.withContext
import java.io.File

/**
 * Comprehensive device hardware and modem detection manager.
 * Detects phone type, modem chipset, radio type, and determines optimal SMS sending strategy.
 * 
 * Supports:
 * - Qualcomm Snapdragon (MSM, SDM, SM series)
 * - MediaTek (Helio, Dimensity)
 * - Samsung Exynos
 * - HiSilicon Kirin (Huawei)
 * - Intel XMM
 * - Spreadtrum/UNISOC
 * - Google Tensor
 * - And fallback for unknown chipsets
 */
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

    private var initialized = false

    /**
     * Initialize device detection (call once on app startup)
     */
    suspend fun initialize(context: Context) {
        if (initialized) return
        runDetection(context)
        initialized = true
    }

    /**
     * Force refresh device detection
     */
    suspend fun refresh(context: Context) {
        runDetection(context)
    }

    private suspend fun runDetection(context: Context) = withContext(Dispatchers.IO) {
        _detectionProgress.value = emptyList()
        appendProgress("🚀 Starting device detection...")

        try {
            // Step 1: Collect base build info
            appendProgress("🔍 Collecting device information...")
            val detectedDeviceInfo = detectDeviceInfo(context)
            _deviceInfo.value = detectedDeviceInfo
            appendProgress("✅ Device: ${detectedDeviceInfo.manufacturer} ${detectedDeviceInfo.model}")

            // Step 2: Detect chipset and radio
            appendProgress("🔧 Detecting chipset & radio...")
            val detectedModemInfo = detectModemInfo(context, detectedDeviceInfo)
            _modemInfo.value = detectedModemInfo
            appendProgress("📡 Chipset: ${detectedModemInfo.chipset.displayName}")
            appendProgress("📶 Radio: ${detectedModemInfo.radioType.displayName}")

            // Step 3: Probe for modem devices
            appendProgress("🔌 Probing modem device paths...")
            val availablePaths = probeModemPaths(detectedModemInfo)
            appendProgress("📁 Found ${availablePaths.size} accessible modem path(s)")

            // Step 4: Determine strategy
            appendProgress("🧪 Determining SMS strategy...")
            val strategy = getRecommendedSmsStrategy()
            appendProgress("🎯 Strategy: ${strategy.displayName}")

            // Step 5: Scan SMS AT capability for detected chipset paths (Qualcomm, MTK, etc.)
            appendProgress("🔬 Scanning AT/SMS capabilities...")
            val atScan = AtCommandManager.scanAtCapabilities(detectedModemInfo)
            _atCapabilityResults.value = atScan
            appendProgress("📊 AT scan: ${atScan.count { it.responded }} responsive port(s)")

            appendProgress("✔ Detection complete")
            Log.i(TAG, "Device: $detectedDeviceInfo")
            Log.i(TAG, "Modem: $detectedModemInfo")
            Log.i(TAG, "Strategy: $strategy")

        } catch (e: Exception) {
            appendProgress("❌ Detection failed: ${e.message}")
            Log.e(TAG, "Detection failure", e)
        }
    }

    /**
     * Detect device manufacturer, model, and hardware details
     */
    private suspend fun detectDeviceInfo(context: Context): DeviceInfo = withContext(Dispatchers.IO) {
        // Get baseband version (modem firmware)
        val basebandVersion = try {
            Build.getRadioVersion() ?: RootAccessManager.getSystemProperty("gsm.version.baseband") ?: "Unknown"
        } catch (e: Exception) {
            "Unknown"
        }

        // Get RIL version
        val rilVersion = RootAccessManager.getSystemProperty("gsm.version.ril-impl") ?: "Unknown"

        // Get bootloader
        val bootloader = Build.BOOTLOADER ?: "Unknown"

        DeviceInfo(
            manufacturer = Build.MANUFACTURER ?: "Unknown",
            model = Build.MODEL ?: "Unknown",
            brand = Build.BRAND ?: "Unknown",
            device = Build.DEVICE ?: "Unknown",
            hardware = Build.HARDWARE ?: "Unknown",
            board = Build.BOARD ?: "Unknown",
            product = Build.PRODUCT ?: "Unknown",
            androidVersion = Build.VERSION.RELEASE ?: "Unknown",
            sdkInt = Build.VERSION.SDK_INT,
            basebandVersion = basebandVersion,
            rilVersion = rilVersion,
            bootloader = bootloader,
            fingerprint = Build.FINGERPRINT ?: "Unknown"
        )
    }

    /**
     * Detect modem chipset and radio type
     */
    private suspend fun detectModemInfo(context: Context, deviceInfo: DeviceInfo): ModemInfo = withContext(Dispatchers.IO) {
        val telephonyManager = try {
            context.getSystemService(Context.TELEPHONY_SERVICE) as? TelephonyManager
        } catch (e: Exception) {
            null
        }

        // Detect chipset based on hardware/board info
        val chipset = detectChipset(deviceInfo)
        appendProgress("   → Chipset identified: ${chipset.name}")

        // Detect radio type
        val radioType = detectRadioType(telephonyManager)
        appendProgress("   → Radio type: ${radioType.displayName}")

        // Get modem device paths for this chipset
        val modemPaths = getModemPathsForChipset(chipset)
        appendProgress("   → ${modemPaths.size} potential modem paths")

        // Detect preferred AT command method
        val atCommandMethod = detectAtCommandMethod(chipset, radioType)
        appendProgress("   → AT method: ${atCommandMethod.displayName}")

        // Get modem-specific properties
        val modemProperties = detectModemProperties(chipset)

        ModemInfo(
            chipset = chipset,
            radioType = radioType,
            modemDevicePaths = modemPaths,
            atCommandMethod = atCommandMethod,
            supportsDirectModemAccess = chipset != ModemChipset.UNKNOWN,
            modemProperties = modemProperties,
            baudRate = getBaudRateForChipset(chipset),
            requiresRootForAt = chipset.requiresRoot
        )
    }

    /**
     * Detect modem chipset from hardware identifiers
     */
    private fun detectChipset(deviceInfo: DeviceInfo): ModemChipset {
        val hardware = deviceInfo.hardware.lowercase()
        val board = deviceInfo.board.lowercase()
        val device = deviceInfo.device.lowercase()
        val product = deviceInfo.product.lowercase()
        val bootloader = deviceInfo.bootloader.lowercase()
        val baseband = deviceInfo.basebandVersion.lowercase()
        val combined = "$hardware $board $device $product"

        Log.d(TAG, "Detecting chipset from: hardware=$hardware, board=$board, device=$device")

        return when {
            // Google Tensor (Pixel 6+)
            combined.contains("tensor") || combined.contains("gs1") || combined.contains("gs2") ||
            bootloader.contains("slider") || bootloader.contains("oriole") || bootloader.contains("raven") ||
            bootloader.contains("cheetah") || bootloader.contains("panther") -> ModemChipset.GOOGLE_TENSOR

            // Qualcomm Snapdragon - Most common
            combined.contains("qcom") || combined.contains("msm") || 
            combined.contains("sdm") || combined.contains("sm8") || combined.contains("sm7") ||
            combined.contains("sm6") || combined.contains("snapdragon") ||
            baseband.contains("mpss") -> {
                when {
                    // Snapdragon 8 Gen series (SM8xxx)
                    combined.contains("sm8550") || combined.contains("sm8650") -> ModemChipset.QUALCOMM_SM8_GEN
                    combined.contains("sm8450") || combined.contains("sm8475") -> ModemChipset.QUALCOMM_SM8_GEN
                    combined.contains("sm8350") || combined.contains("sm8250") -> ModemChipset.QUALCOMM_SM8_GEN
                    
                    // Snapdragon 7xx series
                    combined.contains("sm7") || combined.contains("sdm7") -> ModemChipset.QUALCOMM_SM7XX
                    
                    // Snapdragon 6xx series
                    combined.contains("sm6") || combined.contains("sdm6") -> ModemChipset.QUALCOMM_SM6XX
                    
                    // SDM (older Snapdragon)
                    combined.contains("sdm845") || combined.contains("sdm855") ||
                    combined.contains("sdm865") -> ModemChipset.QUALCOMM_SDM
                    
                    // MSM8xxx series
                    combined.contains("msm89") || combined.contains("msm88") -> ModemChipset.QUALCOMM_MSM8XXX
                    combined.contains("msm8") -> ModemChipset.QUALCOMM_MSM8XXX
                    combined.contains("msm7") -> ModemChipset.QUALCOMM_MSM7XXX
                    
                    else -> ModemChipset.QUALCOMM_GENERIC
                }
            }

            // MediaTek
            combined.contains("mt") && (combined.contains("mt6") || combined.contains("mt8")) ||
            baseband.contains("moly") -> {
                when {
                    // Dimensity 9xxx/8xxx (high-end)
                    combined.contains("mt689") || combined.contains("mt698") ||
                    combined.contains("mt699") -> ModemChipset.MEDIATEK_DIMENSITY_HIGH
                    
                    // Dimensity 7xxx/6xxx (mid-range)  
                    combined.contains("mt678") || combined.contains("mt677") ||
                    combined.contains("mt676") -> ModemChipset.MEDIATEK_DIMENSITY_MID
                    
                    // Helio G/P series
                    combined.contains("mt676") || combined.contains("mt675") ||
                    combined.contains("mt681") || combined.contains("mt682") -> ModemChipset.MEDIATEK_HELIO
                    
                    // Older MediaTek
                    combined.contains("mt67") || combined.contains("mt65") -> ModemChipset.MEDIATEK_GENERIC
                    
                    else -> ModemChipset.MEDIATEK_GENERIC
                }
            }

            // Samsung Exynos
            combined.contains("exynos") || combined.contains("universal") ||
            combined.contains("samsungexynos") -> {
                when {
                    combined.contains("exynos2") || combined.contains("s5e99") -> ModemChipset.SAMSUNG_EXYNOS_2XXX
                    combined.contains("exynos1") || combined.contains("s5e98") -> ModemChipset.SAMSUNG_EXYNOS_1XXX
                    combined.contains("exynos9") || combined.contains("s5e9") -> ModemChipset.SAMSUNG_EXYNOS_9XXX
                    else -> ModemChipset.SAMSUNG_EXYNOS
                }
            }

            // HiSilicon Kirin (Huawei)
            combined.contains("kirin") || combined.contains("hi36") || combined.contains("hi37") ||
            combined.contains("hisi") -> {
                when {
                    combined.contains("kirin99") || combined.contains("kirin98") -> ModemChipset.HISILICON_KIRIN_9XX
                    combined.contains("kirin9") -> ModemChipset.HISILICON_KIRIN_9XX
                    else -> ModemChipset.HISILICON_KIRIN
                }
            }

            // Intel/Infineon (older iPhones via USB, some tablets)
            combined.contains("intel") || combined.contains("infineon") ||
            baseband.contains("xmm") -> ModemChipset.INTEL_XMM

            // Spreadtrum/UNISOC (budget devices)
            combined.contains("spreadtrum") || combined.contains("unisoc") || 
            combined.contains("sc9") || combined.contains("ums") ||
            baseband.contains("unisoc") -> ModemChipset.SPREADTRUM_UNISOC

            // Apple (for reference, won't work on Android but detect it)
            combined.contains("apple") -> ModemChipset.APPLE_BASEBAND

            else -> ModemChipset.UNKNOWN
        }
    }

    /**
     * Detect radio type (GSM/CDMA/LTE/5G)
     */
    private fun detectRadioType(telephonyManager: TelephonyManager?): RadioType {
        if (telephonyManager == null) return RadioType.UNKNOWN

        return try {
            val phoneType = telephonyManager.phoneType
            val networkType = try {
                telephonyManager.dataNetworkType
            } catch (e: SecurityException) {
                TelephonyManager.NETWORK_TYPE_UNKNOWN
            }

            when {
                // 5G NR detection
                networkType == TelephonyManager.NETWORK_TYPE_NR -> RadioType.NR_5G

                // 5G NSA (LTE with NR)
                Build.VERSION.SDK_INT >= 29 && networkType == 20 -> RadioType.NR_5G_NSA

                // LTE/4G (NETWORK_TYPE_LTE_CA = 19, added in API 23)
                networkType == TelephonyManager.NETWORK_TYPE_LTE ||
                networkType == 19 -> RadioType.LTE

                // CDMA variants
                phoneType == TelephonyManager.PHONE_TYPE_CDMA ||
                networkType in listOf(
                    TelephonyManager.NETWORK_TYPE_CDMA,
                    TelephonyManager.NETWORK_TYPE_EVDO_0,
                    TelephonyManager.NETWORK_TYPE_EVDO_A,
                    TelephonyManager.NETWORK_TYPE_EVDO_B,
                    TelephonyManager.NETWORK_TYPE_1xRTT
                ) -> RadioType.CDMA

                // HSPA+ / 3G
                networkType in listOf(
                    TelephonyManager.NETWORK_TYPE_HSPAP,
                    TelephonyManager.NETWORK_TYPE_HSPA,
                    TelephonyManager.NETWORK_TYPE_HSDPA,
                    TelephonyManager.NETWORK_TYPE_HSUPA,
                    TelephonyManager.NETWORK_TYPE_UMTS
                ) -> RadioType.HSPA

                // GSM/EDGE/GPRS (2G)
                phoneType == TelephonyManager.PHONE_TYPE_GSM ||
                networkType in listOf(
                    TelephonyManager.NETWORK_TYPE_GPRS,
                    TelephonyManager.NETWORK_TYPE_EDGE,
                    TelephonyManager.NETWORK_TYPE_GSM
                ) -> RadioType.GSM

                // TD-SCDMA (China)
                networkType == TelephonyManager.NETWORK_TYPE_TD_SCDMA -> RadioType.TD_SCDMA

                // iWLAN (WiFi calling)
                networkType == TelephonyManager.NETWORK_TYPE_IWLAN -> RadioType.IWLAN

                else -> RadioType.UNKNOWN
            }
        } catch (e: Exception) {
            Log.e(TAG, "Error detecting radio type", e)
            RadioType.UNKNOWN
        }
    }

    /**
     * Get modem device paths based on chipset
     */
    private fun getModemPathsForChipset(chipset: ModemChipset): List<String> {
        val paths = mutableListOf<String>()

        // Add chipset-specific paths
        paths.addAll(when (chipset) {
            ModemChipset.QUALCOMM_GENERIC,
            ModemChipset.QUALCOMM_MSM7XXX,
            ModemChipset.QUALCOMM_MSM8XXX,
            ModemChipset.QUALCOMM_SDM,
            ModemChipset.QUALCOMM_SM6XX,
            ModemChipset.QUALCOMM_SM7XX,
            ModemChipset.QUALCOMM_SM8_GEN -> listOf(
                "/dev/smd0", "/dev/smd7", "/dev/smd8", "/dev/smd11",
                "/dev/ttyHS0", "/dev/ttyHSL0", "/dev/ttyHSL1",
                "/dev/at_usb0", "/dev/at_mdm0",
                "/dev/diag", "/dev/diag_mdm"
            )

            ModemChipset.MEDIATEK_GENERIC,
            ModemChipset.MEDIATEK_HELIO,
            ModemChipset.MEDIATEK_DIMENSITY_MID,
            ModemChipset.MEDIATEK_DIMENSITY_HIGH -> listOf(
                "/dev/radio/pttycmd1", "/dev/radio/pttycmd2",
                "/dev/radio/atci1", "/dev/radio/atci2",
                "/dev/ttyMT0", "/dev/ttyMT1", "/dev/ttyMT2",
                "/dev/ttyC0", "/dev/ttyC1",
                "/dev/ccci_uem_tx", "/dev/ccci_uem_rx",
                "/dev/ccci_fs", "/dev/ccci_aud"
            )

            ModemChipset.SAMSUNG_EXYNOS,
            ModemChipset.SAMSUNG_EXYNOS_9XXX,
            ModemChipset.SAMSUNG_EXYNOS_1XXX,
            ModemChipset.SAMSUNG_EXYNOS_2XXX -> listOf(
                "/dev/umts_ipc0", "/dev/umts_rfs0",
                "/dev/umts_boot0", "/dev/umts_multi",
                "/dev/link_pm", "/dev/modem_ctl",
                "/dev/samsung_ipc0", "/dev/dpram0"
            )

            ModemChipset.HISILICON_KIRIN,
            ModemChipset.HISILICON_KIRIN_9XX -> listOf(
                "/dev/appvcom", "/dev/appvcom1", "/dev/appvcom4",
                "/dev/ttyAMA1", "/dev/ttyAMA2",
                "/dev/hisi_at"
            )

            ModemChipset.INTEL_XMM -> listOf(
                "/dev/gsmtty1", "/dev/gsmtty2", "/dev/gsmtty7",
                "/dev/ttyIFX0", "/dev/ttyIFX1",
                "/dev/mdm_ctrl", "/dev/ttyXMM0"
            )

            ModemChipset.SPREADTRUM_UNISOC -> listOf(
                "/dev/stty_lte1", "/dev/stty_lte2", "/dev/stty_lte3",
                "/dev/slog_lte", "/dev/spipe_lte1",
                "/dev/stty_td1", "/dev/stty_td2"
            )

            ModemChipset.GOOGLE_TENSOR -> listOf(
                "/dev/umts_ipc0", "/dev/umts_boot0",
                "/dev/modem_ctrl", "/dev/samsung_ipc"
            )

            ModemChipset.APPLE_BASEBAND -> emptyList() // Not applicable

            ModemChipset.UNKNOWN -> emptyList()
        })

        // Always add generic fallback paths
        paths.addAll(listOf(
            "/dev/ttyUSB0", "/dev/ttyUSB1", "/dev/ttyUSB2", "/dev/ttyUSB3",
            "/dev/ttyACM0", "/dev/ttyACM1",
            "/dev/ttyGS0", "/dev/ttyGS1"
        ))

        return paths.distinct()
    }

    /**
     * Probe which modem paths actually exist and are accessible
     */
    private suspend fun probeModemPaths(modemInfo: ModemInfo): List<String> = withContext(Dispatchers.IO) {
        val available = mutableListOf<String>()

        for (path in modemInfo.modemDevicePaths) {
            try {
                val file = File(path)
                if (file.exists()) {
                    // Check if accessible with root
                    if (RootAccessManager.checkDeviceAccess(path)) {
                        available.add(path)
                        Log.d(TAG, "Modem path accessible: $path")
                    } else {
                        Log.d(TAG, "Modem path exists but not accessible: $path")
                    }
                }
            } catch (e: Exception) {
                Log.w(TAG, "Error checking path $path: ${e.message}")
            }
        }

        available
    }

    /**
     * Determine optimal AT command method based on chipset and radio
     */
    private fun detectAtCommandMethod(chipset: ModemChipset, radioType: RadioType): AtCommandMethod {
        return when (chipset) {
            ModemChipset.QUALCOMM_GENERIC,
            ModemChipset.QUALCOMM_MSM7XXX,
            ModemChipset.QUALCOMM_MSM8XXX,
            ModemChipset.QUALCOMM_SDM,
            ModemChipset.QUALCOMM_SM6XX,
            ModemChipset.QUALCOMM_SM7XX,
            ModemChipset.QUALCOMM_SM8_GEN -> AtCommandMethod.QCRIL_SMD

            ModemChipset.MEDIATEK_GENERIC,
            ModemChipset.MEDIATEK_HELIO -> AtCommandMethod.MEDIATEK_CCCI

            ModemChipset.MEDIATEK_DIMENSITY_MID,
            ModemChipset.MEDIATEK_DIMENSITY_HIGH -> AtCommandMethod.MEDIATEK_CCCI_V2

            ModemChipset.SAMSUNG_EXYNOS,
            ModemChipset.SAMSUNG_EXYNOS_9XXX -> AtCommandMethod.SAMSUNG_IPC

            ModemChipset.SAMSUNG_EXYNOS_1XXX,
            ModemChipset.SAMSUNG_EXYNOS_2XXX -> AtCommandMethod.SAMSUNG_IPC_V2

            ModemChipset.HISILICON_KIRIN,
            ModemChipset.HISILICON_KIRIN_9XX -> AtCommandMethod.HUAWEI_APPVCOM

            ModemChipset.INTEL_XMM -> AtCommandMethod.INTEL_TTY

            ModemChipset.SPREADTRUM_UNISOC -> AtCommandMethod.SPREADTRUM_STTY

            ModemChipset.GOOGLE_TENSOR -> AtCommandMethod.GOOGLE_TENSOR_IPC

            ModemChipset.APPLE_BASEBAND -> AtCommandMethod.UNSUPPORTED

            ModemChipset.UNKNOWN -> AtCommandMethod.STANDARD_TTY
        }
    }

    /**
     * Get baud rate for chipset
     */
    private fun getBaudRateForChipset(chipset: ModemChipset): Int {
        return when (chipset) {
            ModemChipset.QUALCOMM_MSM7XXX -> 9600
            ModemChipset.INTEL_XMM -> 115200
            ModemChipset.SPREADTRUM_UNISOC -> 921600
            else -> 115200 // Default
        }
    }

    /**
     * Detect modem-specific properties via getprop
     */
    private suspend fun detectModemProperties(chipset: ModemChipset): Map<String, String> = withContext(Dispatchers.IO) {
        val props = mutableMapOf<String, String>()

        val propKeys = when (chipset) {
            ModemChipset.QUALCOMM_GENERIC, ModemChipset.QUALCOMM_MSM7XXX,
            ModemChipset.QUALCOMM_MSM8XXX, ModemChipset.QUALCOMM_SDM,
            ModemChipset.QUALCOMM_SM6XX, ModemChipset.QUALCOMM_SM7XX,
            ModemChipset.QUALCOMM_SM8_GEN -> listOf(
                "gsm.version.baseband", "gsm.version.ril-impl",
                "ro.baseband", "persist.radio.multisim.config"
            )

            ModemChipset.MEDIATEK_GENERIC, ModemChipset.MEDIATEK_HELIO,
            ModemChipset.MEDIATEK_DIMENSITY_MID, ModemChipset.MEDIATEK_DIMENSITY_HIGH -> listOf(
                "gsm.version.baseband", "gsm.version.ril-impl",
                "ro.mediatek.chip_ver", "ro.mediatek.platform"
            )

            ModemChipset.SAMSUNG_EXYNOS, ModemChipset.SAMSUNG_EXYNOS_9XXX,
            ModemChipset.SAMSUNG_EXYNOS_1XXX, ModemChipset.SAMSUNG_EXYNOS_2XXX -> listOf(
                "gsm.version.baseband", "ril.modem.board",
                "ro.boot.em.model", "ro.boot.hardware.revision"
            )

            else -> listOf("gsm.version.baseband", "gsm.version.ril-impl")
        }

        for (key in propKeys) {
            try {
                RootAccessManager.getSystemProperty(key)?.let { value ->
                    if (value.isNotEmpty()) {
                        props[key] = value
                    }
                }
            } catch (e: Exception) {
                Log.w(TAG, "Failed to get property $key: ${e.message}")
            }
        }

        props
    }

    /**
     * Get recommended SMS sending strategy based on device capabilities
     */
    fun getRecommendedSmsStrategy(): SmsStrategy {
        val modem = _modemInfo.value ?: return SmsStrategy.STANDARD_API_ONLY
        val device = _deviceInfo.value ?: return SmsStrategy.STANDARD_API_ONLY

        return when {
            // Chipset is completely unsupported
            modem.chipset == ModemChipset.APPLE_BASEBAND -> SmsStrategy.UNSUPPORTED

            // Known chipset with direct modem access support
            modem.supportsDirectModemAccess &&
            modem.chipset != ModemChipset.UNKNOWN &&
            modem.atCommandMethod != AtCommandMethod.UNSUPPORTED -> {
                if (modem.requiresRootForAt) {
                    SmsStrategy.AT_COMMANDS_PRIMARY
                } else {
                    SmsStrategy.AT_WITH_FALLBACK
                }
            }

            // Unknown chipset - try standard TTY with fallback
            modem.chipset == ModemChipset.UNKNOWN -> SmsStrategy.AT_WITH_FALLBACK

            // No direct modem access - standard API only
            else -> SmsStrategy.STANDARD_API_ONLY
        }
    }

    /**
     * Get a summary of device capabilities for UI display
     */
    fun getCapabilitySummary(): DeviceCapabilitySummary {
        val device = _deviceInfo.value
        val modem = _modemInfo.value

        return DeviceCapabilitySummary(
            deviceName = device?.let { "${it.manufacturer} ${it.model}" } ?: "Unknown",
            androidVersion = device?.androidVersion ?: "Unknown",
            chipset = modem?.chipset?.displayName ?: "Unknown",
            radioType = modem?.radioType?.displayName ?: "Unknown",
            atMethod = modem?.atCommandMethod?.displayName ?: "Unknown",
            strategy = getRecommendedSmsStrategy(),
            modemPathCount = modem?.modemDevicePaths?.size ?: 0,
            basebandVersion = device?.basebandVersion ?: "Unknown"
        )
    }

    private fun appendProgress(line: String) {
        val updated = _detectionProgress.value + line
        _detectionProgress.value = updated.takeLast(30)
    }
}

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
    val product: String,
    val androidVersion: String,
    val sdkInt: Int,
    val basebandVersion: String,
    val rilVersion: String,
    val bootloader: String,
    val fingerprint: String
)

/**
 * Modem information
 */
data class ModemInfo(
    val chipset: ModemChipset,
    val radioType: RadioType,
    val modemDevicePaths: List<String>,
    val atCommandMethod: AtCommandMethod,
    val supportsDirectModemAccess: Boolean,
    val modemProperties: Map<String, String>,
    val baudRate: Int,
    val requiresRootForAt: Boolean
)

/**
 * Supported modem chipsets
 */
enum class ModemChipset(val displayName: String, val requiresRoot: Boolean = true) {
    // Qualcomm
    QUALCOMM_GENERIC("Qualcomm Generic"),
    QUALCOMM_MSM7XXX("Qualcomm MSM7xxx"),
    QUALCOMM_MSM8XXX("Qualcomm MSM8xxx"),
    QUALCOMM_SDM("Qualcomm Snapdragon (SDM)"),
    QUALCOMM_SM6XX("Qualcomm Snapdragon 6xx"),
    QUALCOMM_SM7XX("Qualcomm Snapdragon 7xx"),
    QUALCOMM_SM8_GEN("Qualcomm Snapdragon 8 Gen"),

    // MediaTek
    MEDIATEK_GENERIC("MediaTek Generic"),
    MEDIATEK_HELIO("MediaTek Helio"),
    MEDIATEK_DIMENSITY_MID("MediaTek Dimensity (Mid)"),
    MEDIATEK_DIMENSITY_HIGH("MediaTek Dimensity (High)"),

    // Samsung
    SAMSUNG_EXYNOS("Samsung Exynos"),
    SAMSUNG_EXYNOS_9XXX("Samsung Exynos 9xxx"),
    SAMSUNG_EXYNOS_1XXX("Samsung Exynos 1xxx"),
    SAMSUNG_EXYNOS_2XXX("Samsung Exynos 2xxx"),

    // HiSilicon
    HISILICON_KIRIN("HiSilicon Kirin"),
    HISILICON_KIRIN_9XX("HiSilicon Kirin 9xx"),

    // Intel
    INTEL_XMM("Intel XMM"),

    // Spreadtrum
    SPREADTRUM_UNISOC("Spreadtrum/UNISOC"),

    // Google
    GOOGLE_TENSOR("Google Tensor"),

    // Apple (for reference)
    APPLE_BASEBAND("Apple Baseband", requiresRoot = false),

    // Unknown
    UNKNOWN("Unknown", requiresRoot = true)
}

/**
 * Radio technology types
 */
enum class RadioType(val displayName: String) {
    GSM("GSM/GPRS/EDGE (2G)"),
    HSPA("HSPA/UMTS (3G)"),
    LTE("LTE (4G)"),
    NR_5G("5G NR (SA)"),
    NR_5G_NSA("5G NR (NSA)"),
    CDMA("CDMA/EVDO"),
    TD_SCDMA("TD-SCDMA"),
    IWLAN("WiFi Calling"),
    UNKNOWN("Unknown")
}

/**
 * AT command communication methods
 */
enum class AtCommandMethod(val displayName: String) {
    QCRIL_SMD("Qualcomm SMD"),
    MEDIATEK_CCCI("MediaTek CCCI"),
    MEDIATEK_CCCI_V2("MediaTek CCCI v2"),
    SAMSUNG_IPC("Samsung IPC"),
    SAMSUNG_IPC_V2("Samsung IPC v2"),
    HUAWEI_APPVCOM("Huawei APPVCOM"),
    INTEL_TTY("Intel TTY"),
    SPREADTRUM_STTY("Spreadtrum STTY"),
    GOOGLE_TENSOR_IPC("Google Tensor IPC"),
    STANDARD_TTY("Standard TTY"),
    UNSUPPORTED("Unsupported")
}

/**
 * SMS sending strategies
 */
enum class SmsStrategy(val displayName: String) {
    AT_COMMANDS_PRIMARY("AT Commands (Primary)"),
    AT_WITH_FALLBACK("AT Commands + Fallback"),
    STANDARD_API_ONLY("Standard API Only"),
    UNSUPPORTED("Unsupported")
}

/**
 * Summary for UI display
 */
data class DeviceCapabilitySummary(
    val deviceName: String,
    val androidVersion: String,
    val chipset: String,
    val radioType: String,
    val atMethod: String,
    val strategy: SmsStrategy,
    val modemPathCount: Int,
    val basebandVersion: String
)
