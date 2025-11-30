package com.zerosms.testing.core.at

import android.content.Context
import android.util.Log
import com.zerosms.testing.core.device.DeviceInfoManager
import com.zerosms.testing.core.device.ModemChipset
import com.zerosms.testing.core.device.AtCommandMethod
import com.zerosms.testing.core.root.RootAccessManager
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * AT Command Manager - Handles direct modem communication via AT commands for SMS.
 * Requires root access for serial port communication.
 * 
 * Enhanced with DeviceInfoManager integration for chipset-specific modem detection
 * and AT command handling optimized for each chipset type.
 */
object AtCommandManager {
    private const val TAG = "AtCommandManager"

    // Default fallback modem device paths (used if DeviceInfoManager unavailable)
    private val FALLBACK_MODEM_PATHS = listOf(
        "/dev/smd0", "/dev/smd7", "/dev/smd11",
        "/dev/ttyUSB0", "/dev/ttyUSB1", "/dev/ttyUSB2",
        "/dev/ttyACM0", "/dev/ttyACM1",
        "/dev/ttyGS0", "/dev/at_mdm0"
    )

    private var modemDevice: String? = null
    private var rootAvailableCache: Boolean? = null
    private var detectedMethod: AtCommandMethod = AtCommandMethod.STANDARD_TTY

    /** Check if root is available (suspend function) */
    suspend fun isRootAvailable(): Boolean {
        rootAvailableCache?.let { return it }
        val result = RootAccessManager.isRootAvailable()
        rootAvailableCache = result
        return result
    }

    /** Get the detected AT command method for this device */
    fun getDetectedMethod(): AtCommandMethod = detectedMethod

    /** Probe for available modem devices with chipset-aware ordering */
    suspend fun probeDevices(context: Context? = null): List<String> = withContext(Dispatchers.IO) {
        if (!isRootAvailable()) return@withContext emptyList()

        val found = mutableListOf<String>()
        
        // First try chipset-specific paths from DeviceInfoManager if context available
        context?.let { ctx ->
            try {
                val modemInfo = DeviceInfoManager.modemInfo.value
                if (modemInfo != null) {
                    detectedMethod = modemInfo.atCommandMethod
                    Log.i(TAG, "Using chipset-specific paths for ${modemInfo.chipset.displayName}")
                    Log.i(TAG, "AT method: ${modemInfo.atCommandMethod}")
                    
                    // Priority paths from DeviceInfoManager
                    for (path in modemInfo.modemDevicePaths) {
                        if (RootAccessManager.checkDeviceAccess(path)) {
                            found.add(path)
                            Log.d(TAG, "Found chipset path: $path")
                        }
                    }
                }
            } catch (e: Exception) {
                Log.w(TAG, "DeviceInfoManager not available, using fallback paths", e)
            }
        }

        // Fallback: Check default paths
        for (path in FALLBACK_MODEM_PATHS) {
            if (path !in found && RootAccessManager.checkDeviceAccess(path)) {
                found.add(path)
            }
        }
        
        // Also discover via ls
        found.addAll(RootAccessManager.getModemPorts().filter { it !in found })
        found
    }

    /** Initialize AT on a specific device path with chipset-aware configuration */
    suspend fun initializeAtOnDevice(devicePath: String): Boolean = withContext(Dispatchers.IO) {
        if (!isRootAvailable()) {
            Log.e(TAG, "Root not available")
            return@withContext false
        }

        try {
            // Get chipset-specific configuration
            val baudRate = getBaudRateForDevice(devicePath)
            val configCmd = getSerialConfigCommand(devicePath, baudRate)
            
            Log.d(TAG, "Configuring $devicePath with baud rate $baudRate")
            
            // Configure serial port
            val configResult = RootAccessManager.executeRootCommand(configCmd)
            if (!configResult.success) {
                Log.e(TAG, "Failed to configure port: ${configResult.error}")
                return@withContext false
            }

            // Test AT command with chipset-specific timeout
            val timeout = getTimeoutForMethod()
            val atTest = sendAtCommand(devicePath, "AT", timeout)
            if (atTest.contains("OK")) {
                modemDevice = devicePath
                Log.i(TAG, "Modem initialized on $devicePath (method: $detectedMethod)")
                return@withContext true
            }
            
            // Some modems need ATE0 (echo off) first
            val ate0Test = sendAtCommand(devicePath, "ATE0", timeout)
            if (ate0Test.contains("OK") || ate0Test.contains("ATE0")) {
                val atRetry = sendAtCommand(devicePath, "AT", timeout)
                if (atRetry.contains("OK")) {
                    modemDevice = devicePath
                    Log.i(TAG, "Modem initialized on $devicePath after ATE0")
                    return@withContext true
                }
            }
            
            Log.w(TAG, "No OK response from $devicePath")
            false
        } catch (e: Exception) {
            Log.e(TAG, "Init failed on $devicePath", e)
            false
        }
    }

    /** Get appropriate baud rate based on device path and chipset */
    private fun getBaudRateForDevice(devicePath: String): Int {
        return when {
            // QMI/Qualcomm paths often need 9600
            devicePath.contains("qmi") || devicePath.contains("smd") -> 9600
            // USB serial typically 115200
            devicePath.contains("ttyUSB") || devicePath.contains("ttyACM") -> 115200
            // MediaTek CCCI paths
            devicePath.contains("ccci") -> 115200
            // Intel paths
            devicePath.contains("gsmtty") -> 115200
            // Default
            else -> 115200
        }
    }

    /** Get serial configuration command for device */
    private fun getSerialConfigCommand(devicePath: String, baudRate: Int): String {
        return "stty -F $devicePath $baudRate cs8 -cstopb -parenb raw -echo"
    }

    /** Get timeout based on detected AT method */
    private fun getTimeoutForMethod(): Int {
        return when (detectedMethod) {
            AtCommandMethod.QCRIL_SMD -> 5
            AtCommandMethod.MEDIATEK_CCCI -> 3
            AtCommandMethod.MEDIATEK_CCCI_V2 -> 3
            AtCommandMethod.SAMSUNG_IPC -> 5
            AtCommandMethod.SAMSUNG_IPC_V2 -> 5
            AtCommandMethod.HUAWEI_APPVCOM -> 5
            AtCommandMethod.INTEL_TTY -> 3
            AtCommandMethod.SPREADTRUM_STTY -> 3
            AtCommandMethod.GOOGLE_TENSOR_IPC -> 3
            AtCommandMethod.STANDARD_TTY -> 3
            AtCommandMethod.UNSUPPORTED -> 5
        }
    }

    /** Get currently initialized modem device */
    fun getInitializedDevice(): String? = modemDevice

    /** Check if AT commands are ready */
    fun isInitialized(): Boolean = modemDevice != null

    /** Send PDU mode SMS via AT commands */
    suspend fun sendSmsPdu(pdu: String, pduLen: Int): Boolean = withContext(Dispatchers.IO) {
        val device = modemDevice ?: return@withContext false
        try {
            // Set PDU mode
            val modeResp = sendAtCommand(device, "AT+CMGF=0")
            if (!modeResp.contains("OK")) {
                Log.e(TAG, "Failed to set PDU mode")
                return@withContext false
            }

            // Send CMGS command
            val cmgsResp = sendAtCommand(device, "AT+CMGS=$pduLen")
            if (!cmgsResp.contains(">")) {
                Log.e(TAG, "No prompt after CMGS")
                return@withContext false
            }

            // Send PDU data
            val sendResp = sendPduData(device, pdu)
            val success = sendResp.contains("+CMGS:") || sendResp.contains("OK")
            Log.d(TAG, "SMS send result: $success")
            success
        } catch (e: Exception) {
            Log.e(TAG, "PDU send failed", e)
            false
        }
    }

    /** Send text mode SMS (simpler fallback) */
    suspend fun sendSmsText(destination: String, message: String): Boolean = withContext(Dispatchers.IO) {
        val device = modemDevice ?: return@withContext false
        try {
            // Set text mode
            val modeResp = sendAtCommand(device, "AT+CMGF=1")
            if (!modeResp.contains("OK")) {
                Log.e(TAG, "Failed to set text mode")
                return@withContext false
            }

            // Send CMGS command
            val cmgsResp = sendAtCommand(device, "AT+CMGS=\"$destination\"")
            if (!cmgsResp.contains(">")) {
                Log.e(TAG, "No prompt after CMGS")
                return@withContext false
            }

            // Send message text with Ctrl+Z
            val sendResp = sendTextData(device, message)
            val success = sendResp.contains("+CMGS:") || sendResp.contains("OK")
            Log.d(TAG, "Text SMS send result: $success")
            success
        } catch (e: Exception) {
            Log.e(TAG, "Text send failed", e)
            false
        }
    }

    /** Build PDU for flash SMS (class 0) */
    fun buildFlashSmsPdu(destination: String, message: String): Pair<String, Int> {
        // GSM 03.40 SMS-SUBMIT PDU
        val pduBuilder = StringBuilder()

        // SMSC length (00 = use default)
        pduBuilder.append("00")

        // First octet: SMS-SUBMIT (01), no VP, no SRR, no UDHI
        pduBuilder.append("11")

        // Message reference (00 = let network assign)
        pduBuilder.append("00")

        // Destination address
        val cleanDest = destination.replace("+", "").replace("-", "").replace(" ", "")
        val addrLen = cleanDest.length
        pduBuilder.append(String.format("%02X", addrLen))

        // Type of address: 91 for international, 81 for national
        val toa = if (destination.startsWith("+")) "91" else "81"
        pduBuilder.append(toa)

        // Encode destination (swap nibbles)
        pduBuilder.append(swapNibbles(cleanDest))

        // Protocol identifier (00 = SMS)
        pduBuilder.append("00")

        // Data coding scheme: 0x10 = Class 0 (flash), GSM 7-bit
        pduBuilder.append("10")

        // No validity period (handled by first octet)

        // User data
        val encoded = encodeGsm7bit(message)
        pduBuilder.append(String.format("%02X", message.length))
        pduBuilder.append(encoded)

        val pdu = pduBuilder.toString()
        // TPDU length = PDU length minus SMSC bytes (1 byte = 2 hex chars)
        val tpduLen = (pdu.length - 2) / 2
        return Pair(pdu, tpduLen)
    }

    /** GSM 7-bit encoding */
    private fun encodeGsm7bit(text: String): String {
        val gsm7bitChars = "@£\$¥èéùìòÇ\nØø\rÅåΔ_ΦΓΛΩΠΨΣΘΞ ÆæßÉ !\"#¤%&'()*+,-./0123456789:;<=>?" +
            "¡ABCDEFGHIJKLMNOPQRSTUVWXYZÄÖÑÜ§¿abcdefghijklmnopqrstuvwxyzäöñüà"

        val septets = mutableListOf<Int>()
        for (c in text) {
            val idx = gsm7bitChars.indexOf(c)
            septets.add(if (idx >= 0) idx else 0x3F) // '?' for unknown
        }

        // Pack 7-bit septets into 8-bit octets
        val octets = mutableListOf<Int>()
        var shift = 0
        var carry = 0

        for (i in septets.indices) {
            if (shift == 7) {
                octets.add(carry)
                shift = 0
                carry = 0
            }
            val current = septets[i]
            val octet = ((current shl shift) or carry) and 0xFF
            carry = current shr (7 - shift)
            octets.add(octet)
            shift++
        }
        if (shift > 0 && carry > 0) {
            octets.add(carry)
        }

        return octets.joinToString("") { String.format("%02X", it) }
    }

    private fun swapNibbles(num: String): String {
        val padded = if (num.length % 2 != 0) num + "F" else num
        return padded.chunked(2) { "${it[1]}${it[0]}" }.joinToString("")
    }

    private suspend fun sendAtCommand(devicePath: String, command: String, timeout: Int = 3): String = withContext(Dispatchers.IO) {
        try {
            Log.d(TAG, "AT Command: $command (timeout: ${timeout}s)")
            val result = RootAccessManager.executeRootCommand(
                "stty -F $devicePath $(stty -F $devicePath -g 2>/dev/null || echo '115200 cs8'); echo -ne \"$command\\r\\n\" > $devicePath; timeout $timeout cat $devicePath 2>/dev/null || true"
            )
            if (result.success) result.output else "ERROR: ${result.error}"
        } catch (e: Exception) {
            "ERROR: ${e.message}"
        }
    }

    private suspend fun sendPduData(devicePath: String, pdu: String): String = withContext(Dispatchers.IO) {
        try {
            // Send PDU followed by Ctrl+Z (0x1A)
            val result = RootAccessManager.executeRootCommand(
                "echo -ne \"$pdu\\x1a\" > $devicePath; timeout 5 cat $devicePath"
            )
            if (result.success) result.output else "ERROR: ${result.error}"
        } catch (e: Exception) {
            "ERROR: ${e.message}"
        }
    }

    private suspend fun sendTextData(devicePath: String, message: String): String = withContext(Dispatchers.IO) {
        try {
            // Escape special chars and send with Ctrl+Z
            val escaped = message.replace("\"", "\\\"").replace("'", "\\'")
            val result = RootAccessManager.executeRootCommand(
                "echo -ne \"$escaped\\x1a\" > $devicePath; timeout 5 cat $devicePath"
            )
            if (result.success) result.output else "ERROR: ${result.error}"
        } catch (e: Exception) {
            "ERROR: ${e.message}"
        }
    }

    /** Get service center address from modem */
    suspend fun getServiceCenterAddress(): String? = withContext(Dispatchers.IO) {
        val device = modemDevice ?: return@withContext null
        try {
            val resp = sendAtCommand(device, "AT+CSCA?")
            resp.lines().firstOrNull { it.startsWith("+CSCA:") }
                ?.substringAfter("\"")
                ?.substringBefore("\"")
        } catch (e: Exception) {
            Log.e(TAG, "Failed to get SMSC", e)
            null
        }
    }

    /**
     * Auto-initialize modem using DeviceInfoManager for intelligent device detection.
     * This tries chipset-specific paths first, then falls back to standard probing.
     * 
     * @param context Android context for DeviceInfoManager
     * @return true if modem initialized successfully
     */
    suspend fun autoInitialize(context: Context): Boolean = withContext(Dispatchers.IO) {
        if (!isRootAvailable()) {
            Log.e(TAG, "Root not available, cannot auto-initialize modem")
            return@withContext false
        }

        // Ensure DeviceInfoManager has run detection
        try {
            DeviceInfoManager.initialize(context)
        } catch (e: Exception) {
            Log.w(TAG, "DeviceInfoManager initialization failed", e)
        }

        // Probe for devices with context awareness
        val devices = probeDevices(context)
        if (devices.isEmpty()) {
            Log.e(TAG, "No modem devices found")
            return@withContext false
        }

        Log.i(TAG, "Found ${devices.size} potential modem device(s): $devices")

        // Try each device in order (chipset-specific paths should be first)
        for (device in devices) {
            Log.d(TAG, "Attempting to initialize: $device")
            if (initializeAtOnDevice(device)) {
                Log.i(TAG, "Successfully initialized modem on $device")
                return@withContext true
            }
        }

        Log.e(TAG, "Failed to initialize any modem device")
        false
    }

    /**
     * Get diagnostic info about current modem configuration
     */
    suspend fun getDiagnosticInfo(): Map<String, String> = withContext(Dispatchers.IO) {
        val info = mutableMapOf<String, String>()
        
        info["rootAvailable"] = (rootAvailableCache ?: false).toString()
        info["modemDevice"] = modemDevice ?: "none"
        info["atMethod"] = detectedMethod.toString()
        info["isInitialized"] = isInitialized().toString()
        
        modemDevice?.let { device ->
            // Try to get signal quality
            try {
                val csq = sendAtCommand(device, "AT+CSQ")
                if (csq.contains("+CSQ:")) {
                    info["signalQuality"] = csq.substringAfter("+CSQ:").trim().substringBefore("\n")
                }
            } catch (e: Exception) {
                info["signalQuality"] = "error"
            }
            
            // Try to get operator
            try {
                val cops = sendAtCommand(device, "AT+COPS?")
                if (cops.contains("+COPS:")) {
                    info["operator"] = cops.substringAfter("+COPS:").trim().substringBefore("\n")
                }
            } catch (e: Exception) {
                info["operator"] = "error"
            }
            
            // Try to get IMEI
            try {
                val imei = sendAtCommand(device, "AT+CGSN")
                val imeiVal = imei.lines().firstOrNull { it.matches(Regex("\\d{15}")) }
                if (imeiVal != null) {
                    info["imei"] = imeiVal
                }
            } catch (e: Exception) {
                info["imei"] = "error"
            }
        }
        
        info
    }

    /** Reset state */
    fun reset() {
        modemDevice = null
        rootAvailableCache = null
        detectedMethod = AtCommandMethod.STANDARD_TTY
    }
}
