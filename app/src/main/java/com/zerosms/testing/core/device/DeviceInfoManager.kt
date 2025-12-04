package com.zerosms.testing.core.device

import android.content.Context
import android.os.Build
import android.telephony.TelephonyManager
import android.util.Log
import com.zerosms.testing.core.at.AtCapabilityScanResult

import com.zerosms.testing.core.root.RootAccessManager
import com.zerosms.testing.core.root.RootActivityType
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import java.io.File

/**
 * Manages device hardware information detection
 * Detects phone type, modem chipset, radio type, and determines optimal SMS sending strategy
 */
object DeviceInfoManager {
    private const val TAG = "DeviceInfoManager"

    private val _deviceInfo = MutableStateFlow<DeviceInfo?>(null)
    val deviceInfo: StateFlow<DeviceInfo?> = _deviceInfo.asStateFlow()

    private val _modemInfo = MutableStateFlow<ModemInfo?>(null)
    val modemInfo: StateFlow<ModemInfo?> = _modemInfo.asStateFlow()

    // Detection progress lines (verbose for UI)
    private val _detectionProgress = MutableStateFlow<List<String>>(emptyList())
    val detectionProgress: StateFlow<List<String>> = _detectionProgress.asStateFlow()
    private val _atCapabilityResults = MutableStateFlow<List<AtCapabilityScanResult>>(emptyList())
    val atCapabilityResults: StateFlow<List<AtCapabilityScanResult>> = _atCapabilityResults.asStateFlow()

    // Detection state
    private val _isDetecting = MutableStateFlow(false)
    val isDetecting: StateFlow<Boolean> = _isDetecting.asStateFlow()

    // Current detection job (for cancellation / refresh)
    private var detectionJob: Job? = null
    private val detectionMutex = Mutex()

    /**
     * Initialize device detection (skips if already completed)
     */
    suspend fun initialize(context: Context) {
        Log.i(TAG, "initialize() called - force=false")
        runDetection(context, force = false)
    }

    /**
     * Refresh/rescan device detection (forces re-detection)
     */
    suspend fun refresh(context: Context) {
        Log.i(TAG, "refresh() called - force=true, clearing previous state")
        runDetection(context, force = true)
    }

    fun cancelDetection() {
        Log.w(TAG, "cancelDetection() called by user")
        detectionJob?.cancel()
        detectionJob = null
        _isDetecting.value = false
        appendProgress("✋ Detection cancelled by user")
        RootAccessManager.logActivity("Detection cancelled by user", RootActivityType.WARNING)
    }

    private suspend fun runDetection(context: Context, force: Boolean) {
        detectionMutex.withLock {
            // Check if already running
            if (_isDetecting.value) {
                Log.w(TAG, "Detection already in progress, skipping")
                appendProgress("⏳ Detection already in progress...")
                return
            }

            // Check if already completed (only skip if not forcing)
            if (!force && _deviceInfo.value != null && _modemInfo.value != null) {
                Log.i(TAG, "Detection already completed, skipping (use refresh to force)")
                return
            }

            // Cancel any existing job
            detectionJob?.cancel()
            
            // Clear previous state if forcing refresh
            if (force) {
                Log.d(TAG, "Forcing refresh - clearing previous detection data")
                _deviceInfo.value = null
                _modemInfo.value = null
            }
            
            _detectionProgress.value = emptyList()
            _isDetecting.value = true
        }

        // Launch detection in IO scope
        detectionJob = CoroutineScope(Dispatchers.IO).launch {
            try {
                Log.i(TAG, "========== DEVICE DETECTION STARTED ==========")
                appendProgress("🚀 Starting device detection...")
                RootAccessManager.logActivity("Starting device detection...", RootActivityType.INFO)

                // Step 1: Collect build info
                Log.d(TAG, "Step 1: Collecting base build info")
                appendProgress("🔍 Collecting base build info...")
                
                Log.v(TAG, "  Build.MANUFACTURER = ${Build.MANUFACTURER}")
                Log.v(TAG, "  Build.MODEL = ${Build.MODEL}")
                Log.v(TAG, "  Build.BRAND = ${Build.BRAND}")
                Log.v(TAG, "  Build.DEVICE = ${Build.DEVICE}")
                Log.v(TAG, "  Build.HARDWARE = ${Build.HARDWARE}")
                Log.v(TAG, "  Build.BOARD = ${Build.BOARD}")
                Log.v(TAG, "  Build.VERSION.RELEASE = ${Build.VERSION.RELEASE}")
                Log.v(TAG, "  Build.VERSION.SDK_INT = ${Build.VERSION.SDK_INT}")
                
                val detectedDeviceInfo = detectDeviceInfo(context)
                
                appendProgress("  📱 Manufacturer: ${detectedDeviceInfo.manufacturer}")
                appendProgress("  📱 Model: ${detectedDeviceInfo.model}")
                appendProgress("  📱 Hardware: ${detectedDeviceInfo.hardware}")
                appendProgress("  📱 Board: ${detectedDeviceInfo.board}")
                appendProgress("  📱 Android: ${detectedDeviceInfo.androidVersion} (SDK ${detectedDeviceInfo.sdkInt})")
                appendProgress("  📱 Baseband: ${detectedDeviceInfo.basebandVersion}")
                appendProgress("✅ Device identified: ${detectedDeviceInfo.manufacturer} ${detectedDeviceInfo.model}")
                
                Log.i(TAG, "Device identified: ${detectedDeviceInfo.manufacturer} ${detectedDeviceInfo.model}")
                Log.d(TAG, "Full DeviceInfo: $detectedDeviceInfo")

                // Step 2: Detect chipset
                Log.d(TAG, "Step 2: Detecting chipset from hardware identifiers")
                appendProgress("🔧 Detecting chipset & radio...")
                appendProgress("  🔍 Analyzing: hardware=${Build.HARDWARE}, board=${Build.BOARD}")
                
                Log.d(TAG, "Detecting chipset from: hardware=${Build.HARDWARE}, board=${Build.BOARD}, device=${Build.DEVICE}")
                
                val detectedModemInfo = detectModemInfo(context)
                
                appendProgress("  📡 Chipset: ${detectedModemInfo.chipset.displayName}")
                appendProgress("  📶 Radio type: ${detectedModemInfo.radioType.displayName}")
                appendProgress("  🔌 AT method: ${detectedModemInfo.atCommandMethod}")
                appendProgress("  🔓 Direct modem access: ${if (detectedModemInfo.supportsDirectModemAccess) "Supported" else "Not supported"}")
                
                Log.i(TAG, "Chipset detected: ${detectedModemInfo.chipset.displayName}")
                Log.i(TAG, "Radio type: ${detectedModemInfo.radioType.displayName}")
                Log.i(TAG, "AT command method: ${detectedModemInfo.atCommandMethod}")

                // Step 3: Scan modem paths
                Log.d(TAG, "Step 3: Scanning modem device paths")
                appendProgress("🔍 Scanning modem device paths...")
                
                val accessiblePaths = mutableListOf<String>()
                for (path in detectedModemInfo.modemDevicePaths) {
                    val file = File(path)
                    val exists = file.exists()
                    if (exists) {
                        accessiblePaths.add(path)
                        Log.d(TAG, "  ✓ Modem path accessible: $path")
                        appendProgress("  ✓ Found: $path")
                    } else {
                        Log.v(TAG, "  ✗ Modem path not found: $path")
                    }
                }
                
                if (accessiblePaths.isEmpty()) {
                    appendProgress("  ⚠️ No modem paths accessible (may need root)")
                    Log.w(TAG, "No modem paths accessible - root may be required")
                } else {
                    appendProgress("  📂 ${accessiblePaths.size} modem path(s) found")
                    Log.i(TAG, "Found ${accessiblePaths.size} accessible modem paths")
                }

                // Step 4: Determine SMS strategy
                Log.d(TAG, "Step 4: Determining SMS strategy")
                appendProgress("🧪 Determining SMS strategy...")
                
                _deviceInfo.value = detectedDeviceInfo
                _modemInfo.value = detectedModemInfo
                
                val rootAvailable = RootAccessManager.rootAvailable.value == true
                appendProgress("  🔐 Root access: ${if (rootAvailable) "Available" else "Not available"}")
                Log.d(TAG, "Root access available: $rootAvailable")
                
                val strategy = getRecommendedSmsStrategy()
                appendProgress("🎯 Strategy: $strategy")
                
                Log.i(TAG, "Recommended SMS strategy: $strategy")

                // Complete
                appendProgress("✔ Detection complete")
                Log.i(TAG, "========== DEVICE DETECTION COMPLETE ==========")
                Log.i(TAG, "Device: $detectedDeviceInfo")
                Log.i(TAG, "Modem: $detectedModemInfo")
                Log.i(TAG, "Strategy: $strategy")
                
                RootAccessManager.logActivity(
                    "Detection complete. Chipset: ${detectedModemInfo.chipset.displayName}, Strategy: $strategy",
                    RootActivityType.SUCCESS
                )
                
            } catch (e: Exception) {
                Log.e(TAG, "========== DEVICE DETECTION FAILED ==========", e)
                appendProgress("❌ Detection failed: ${e.message}")
                RootAccessManager.logActivity("Detection failed: ${e.message}", RootActivityType.ERROR)
            } finally {
                _isDetecting.value = false
                Log.d(TAG, "Detection job finished, isDetecting=false")
            }
        }
    }

    /**
     * Detect device manufacturer, model, and hardware details
     */
    private fun detectDeviceInfo(context: Context): DeviceInfo {
        return DeviceInfo(
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

    /**
     * Detect modem chipset and radio type
     */
    private fun detectModemInfo(context: Context): ModemInfo {
        val telephonyManager = context.getSystemService(Context.TELEPHONY_SERVICE) as TelephonyManager
        
        // Detect chipset based on hardware/board info
        val chipset = detectChipset()
        
        // Detect radio type
        val radioType = detectRadioType(telephonyManager)
        
        // Get modem device paths
        val modemPaths = getModemPaths(chipset)
        
        // Detect preferred AT command method
        val atCommandMethod = detectAtCommandMethod(chipset, radioType)
        
        return ModemInfo(
            chipset = chipset,
            radioType = radioType,
            modemDevicePaths = modemPaths,
            atCommandMethod = atCommandMethod,
            supportsDirectModemAccess = chipset != ModemChipset.UNKNOWN
        )
    }

    /**
     * Detect modem chipset from hardware identifiers
     */
    private fun detectChipset(): ModemChipset {
        val hardware = Build.HARDWARE.lowercase()
        val board = Build.BOARD.lowercase()
        val device = Build.DEVICE.lowercase()
        val combined = "$hardware $board $device"

        return when {
            // Qualcomm Snapdragon - Enhanced detection for all variants
            combined.contains("qcom") || combined.contains("msm") || 
            combined.contains("sdm") || combined.contains("sm") ||
            combined.contains("snapdragon") || combined.contains("kona") ||
            combined.contains("lahaina") || combined.contains("monaco") ||
            combined.contains("holi") || combined.contains("skiff") ||
            combined.contains("taro") || combined.contains("parrot") -> {
                when {
                    combined.contains("msm8") -> ModemChipset.QUALCOMM_MSM8XXX
                    combined.contains("msm7") -> ModemChipset.QUALCOMM_MSM7XXX
                    combined.contains("sdm") || combined.contains("sm8") -> ModemChipset.QUALCOMM_SDM
                    // Newer codenames (5G capable)
                    combined.contains("kona") || combined.contains("lahaina") ||
                    combined.contains("monaco") || combined.contains("holi") ||
                    combined.contains("skiff") || combined.contains("taro") ||
                    combined.contains("parrot") -> ModemChipset.QUALCOMM_SDM
                    else -> ModemChipset.QUALCOMM_GENERIC
                }
            }
            
            // MediaTek
            combined.contains("mt") && (combined.contains("mt6") || combined.contains("mt8")) -> {
                when {
                    combined.contains("mt67") || combined.contains("mt68") -> ModemChipset.MEDIATEK_HELIO
                    combined.contains("mt81") || combined.contains("mt89") -> ModemChipset.MEDIATEK_DIMENSITY
                    else -> ModemChipset.MEDIATEK_GENERIC
                }
            }
            
            // Samsung Exynos
            combined.contains("exynos") || combined.contains("universal") -> ModemChipset.SAMSUNG_EXYNOS
            
            // HiSilicon Kirin (Huawei)
            combined.contains("kirin") || combined.contains("hi36") || combined.contains("hi37") -> ModemChipset.HISILICON_KIRIN
            
            // Intel/Infineon
            combined.contains("intel") || combined.contains("infineon") -> ModemChipset.INTEL_XMM
            
            // Spreadtrum/UNISOC
            combined.contains("spreadtrum") || combined.contains("unisoc") || 
            combined.contains("sc") && combined.contains("sc9") -> ModemChipset.SPREADTRUM
            
            else -> ModemChipset.UNKNOWN
        }
    }

    /**
     * Detect radio type (GSM/CDMA/LTE/5G)
     */
    private fun detectRadioType(telephonyManager: TelephonyManager): RadioType {
        return try {
            val phoneType = telephonyManager.phoneType
            val networkType = telephonyManager.dataNetworkType
            
            when {
                // 5G detection
                networkType == TelephonyManager.NETWORK_TYPE_NR -> RadioType.NR_5G
                
                // LTE detection
                networkType == TelephonyManager.NETWORK_TYPE_LTE -> RadioType.LTE
                
                // CDMA variants
                phoneType == TelephonyManager.PHONE_TYPE_CDMA ||
                networkType in listOf(
                    TelephonyManager.NETWORK_TYPE_CDMA,
                    TelephonyManager.NETWORK_TYPE_EVDO_0,
                    TelephonyManager.NETWORK_TYPE_EVDO_A,
                    TelephonyManager.NETWORK_TYPE_EVDO_B,
                    TelephonyManager.NETWORK_TYPE_1xRTT
                ) -> RadioType.CDMA
                
                // GSM variants (default for most)
                phoneType == TelephonyManager.PHONE_TYPE_GSM ||
                networkType in listOf(
                    TelephonyManager.NETWORK_TYPE_GPRS,
                    TelephonyManager.NETWORK_TYPE_EDGE,
                    TelephonyManager.NETWORK_TYPE_UMTS,
                    TelephonyManager.NETWORK_TYPE_HSDPA,
                    TelephonyManager.NETWORK_TYPE_HSUPA,
                    TelephonyManager.NETWORK_TYPE_HSPA,
                    TelephonyManager.NETWORK_TYPE_HSPAP
                ) -> RadioType.GSM
                
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
    private fun getModemPaths(chipset: ModemChipset): List<String> {
        return when (chipset) {
            ModemChipset.QUALCOMM_GENERIC,
            ModemChipset.QUALCOMM_MSM7XXX,
            ModemChipset.QUALCOMM_MSM8XXX,
            ModemChipset.QUALCOMM_SDM -> getQualcommModemPaths()
            
            ModemChipset.MEDIATEK_GENERIC,
            ModemChipset.MEDIATEK_HELIO,
            ModemChipset.MEDIATEK_DIMENSITY -> listOf(
                "/dev/radio/pttycmd1",
                "/dev/radio/atci1",
                "/dev/ttyMT0",
                "/dev/ttyMT1",
                "/dev/ttyMT2",
                "/dev/ccci_uem_tx",
                "/dev/ccci_uem_rx"
            )
            
            ModemChipset.SAMSUNG_EXYNOS -> listOf(
                "/dev/umts_ipc0",
                "/dev/umts_rfs0",
                "/dev/umts_boot0",
                "/dev/link_pm",
                "/dev/modem_ctl"
            )
            
            ModemChipset.HISILICON_KIRIN -> listOf(
                "/dev/appvcom",
                "/dev/appvcom4",
                "/dev/ttyUSB0",
                "/dev/ttyUSB1"
            )
            
            ModemChipset.INTEL_XMM -> listOf(
                "/dev/gsmtty1",
                "/dev/gsmtty7",
                "/dev/ttyIFX0"
            )
            
            ModemChipset.SPREADTRUM -> listOf(
                "/dev/stty_lte1",
                "/dev/stty_lte2",
                "/dev/slog_lte"
            )
            
            ModemChipset.UNKNOWN -> listOf(
                "/dev/smd0",
                "/dev/smd11",
                "/dev/ttyUSB0",
                "/dev/ttyUSB1",
                "/dev/ttyUSB2"
            )
        }
    }

    /**
     * Returns all known Qualcomm modem device paths, including Inseego-specific ports.
     * Covers SMD, TTYHS, USB, DIAG, and WWAN interfaces.
     */
    private fun getQualcommModemPaths(): List<String> = listOf(
        // SMD (Shared Memory Device) interfaces
        "/dev/smd0", "/dev/smd1", "/dev/smd2", "/dev/smd3", "/dev/smd4", "/dev/smd5", "/dev/smd6", "/dev/smd7", "/dev/smd8", "/dev/smd9", "/dev/smd10", "/dev/smd11",
        // TTYHS (High-Speed UART) interfaces
        "/dev/ttyHS0", "/dev/ttyHS1", "/dev/ttyHS2", "/dev/ttyHS3",
        // USB serial interfaces (for external modems or diag)
        "/dev/ttyUSB0", "/dev/ttyUSB1", "/dev/ttyUSB2", "/dev/ttyUSB3",
        // DIAG interface (diagnostic, sometimes used for AT)
        "/dev/diag",
        // WWAN interfaces (Inseego and some MDM modems)
        "/dev/wwan0at", "/dev/wwan1at", "/dev/wwan2at", "/dev/wwan3at",
        // QMI/MBIM (rare, but some Inseego/Netgear)
        "/dev/cdc-wdm0", "/dev/cdc-wdm1",
        // Misc legacy/variant
        "/dev/ts0710mux0", "/dev/ts0710mux1", "/dev/ts0710mux2", "/dev/ts0710mux3",
        // Inseego-specific (observed on some models)
        "/dev/ttyUSB_DIAG", "/dev/ttyUSB_AT", "/dev/ttyUSB_MODEM", "/dev/ttyUSB_NMEA"
    )

    /**
     * Determine optimal AT command method based on chipset and radio
     */
    private fun detectAtCommandMethod(chipset: ModemChipset, radioType: RadioType): AtCommandMethod {
        return when {
            // Qualcomm devices typically use SMD
            chipset == ModemChipset.QUALCOMM_GENERIC ||
            chipset == ModemChipset.QUALCOMM_MSM7XXX ||
            chipset == ModemChipset.QUALCOMM_MSM8XXX ||
            chipset == ModemChipset.QUALCOMM_SDM -> AtCommandMethod.QCRIL_SMD
            
            // MediaTek uses CCCI interface
            chipset == ModemChipset.MEDIATEK_GENERIC ||
            chipset == ModemChipset.MEDIATEK_HELIO ||
            chipset == ModemChipset.MEDIATEK_DIMENSITY -> AtCommandMethod.MEDIATEK_CCCI
            
            // Samsung Exynos uses IPC interface
            chipset == ModemChipset.SAMSUNG_EXYNOS -> AtCommandMethod.SAMSUNG_IPC
            
            // HiSilicon/Huawei
            chipset == ModemChipset.HISILICON_KIRIN -> AtCommandMethod.HUAWEI_APPVCOM
            
            // Intel modems
            chipset == ModemChipset.INTEL_XMM -> AtCommandMethod.INTEL_TTY
            
            // Spreadtrum
            chipset == ModemChipset.SPREADTRUM -> AtCommandMethod.SPREADTRUM_STTY
            
            // Unknown - try standard methods
            else -> AtCommandMethod.STANDARD_TTY
        }
    }

    /**
     * Get recommended SMS sending strategy based on device capabilities
     */
    fun getRecommendedSmsStrategy(): SmsStrategy {
        val modem = _modemInfo.value ?: return SmsStrategy.STANDARD_API_ONLY
        val device = _deviceInfo.value ?: return SmsStrategy.STANDARD_API_ONLY

        return when {
            // Root available and known chipset with direct modem access
            RootAccessManager.rootAvailable.value == true &&
            modem.supportsDirectModemAccess &&
            modem.chipset != ModemChipset.UNKNOWN -> {
                RootAccessManager.logActivity(
                    "Using AT command method: ${modem.atCommandMethod}",
                    RootActivityType.INFO
                )
                SmsStrategy.AT_COMMANDS_PRIMARY
            }
            
            // Root available but unknown chipset - try AT with fallback
            RootAccessManager.rootAvailable.value == true -> {
                RootAccessManager.logActivity(
                    "Unknown chipset, attempting AT with fallback",
                    RootActivityType.WARNING
                )
                SmsStrategy.AT_WITH_FALLBACK
            }
            
            // No root - standard API only
            else -> {
                RootAccessManager.logActivity(
                    "No root access, using standard SMS API",
                    RootActivityType.INFO
                )
                SmsStrategy.STANDARD_API_ONLY
            }
        }
    }

    private fun appendProgress(line: String) {
        Log.d(TAG, "[Progress] $line")
        val updated = _detectionProgress.value + line
        _detectionProgress.value = updated.takeLast(50) // cap to last 50 lines for more verbose output
    }
}


