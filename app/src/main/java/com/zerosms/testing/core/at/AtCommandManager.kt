package com.zerosms.testing.core.at

import android.util.Log
import com.zerosms.testing.core.root.RootAccessManager
import com.zerosms.testing.core.model.Message
import com.zerosms.testing.core.model.MessageType
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.withContext
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream

/**
 * AT Command Manager
 * 
 * Handles direct modem communication via AT commands for SMS operations.
 * Requires root access for serial port communication.
 * 
 * Common AT Commands:
 * - AT+CMGF=0/1  : Set SMS format (0=PDU, 1=Text)
 * - AT+CMGS      : Send SMS
 * - AT+CMGW      : Write SMS to storage
 * - AT+CMGL      : List messages
 * - AT+CSCA      : Set/Get Service Center Address
 * - AT+CSMS      : Select Message Service
 */
class AtCommandManager(
    private val rootManager: RootAccessManager
) {
    
    private val TAG = "AtCommandManager"
    
    // Common modem device paths in priority order
    private val MODEM_DEVICE_PATHS = listOf(
        "/dev/smd0",
        "/dev/smd11",
        "/dev/smd7",
        "/dev/ttyUSB0",
        "/dev/ttyUSB1",
        "/dev/ttyUSB2",
        "/dev/ttyACM0",
        "/dev/ttyGS0"
    )
    
    private var modemDevice: String? = null
    
    /**
     * Initialize AT command interface
     * Detects and configures modem device
     */
    suspend fun initialize(): Boolean = withContext(Dispatchers.IO) {
        Log.d(TAG, "Initializing AT command interface...")
        
        // Check root access first
        if (!rootManager.isRootAvailable()) {
            Log.e(TAG, "Root access not available")
            return@withContext false
        }
        
        // Find available modem device
        for (devicePath in MODEM_DEVICE_PATHS) {
            if (rootManager.checkDeviceAccess(devicePath)) {
                Log.d(TAG, "Found modem device: $devicePath")
                
                // Test with basic AT command
                if (testDevice(devicePath)) {
                    modemDevice = devicePath
                    Log.i(TAG, "Successfully initialized modem: $devicePath")
                    return@withContext true
                }
            }
        }
        
        // Try discovering via ls
        val discoveredPorts = rootManager.getModemPorts()
        Log.d(TAG, "Discovered ports: $discoveredPorts")
        
        for (port in discoveredPorts) {
            if (testDevice(port)) {
                modemDevice = port
                Log.i(TAG, "Successfully initialized modem: $port")
                return@withContext true
            }
        }
        
        Log.e(TAG, "No working modem device found")
        return@withContext false
    }
    
    /**
     * Test if device responds to AT commands
     */
    private suspend fun testDevice(devicePath: String): Boolean = withContext(Dispatchers.IO) {
        try {
            val response = sendAtCommand(devicePath, "AT")
            response.contains("OK")
        } catch (e: Exception) {
            Log.e(TAG, "Device test failed: $devicePath", e)
            false
        }
    }
    
    /**
     * Send SMS using AT commands (PDU mode)
     * Supports Class 0 (Flash) and Type 0 (Silent) SMS
     */
    suspend fun sendSmsViaAt(message: Message): Result<String> = withContext(Dispatchers.IO) {
        try {
            val device = modemDevice ?: return@withContext Result.failure(
                Exception("AT command interface not initialized")
            )
            
            // Set PDU mode
            var response = sendAtCommand(device, "AT+CMGF=0")
            if (!response.contains("OK")) {
                return@withContext Result.failure(Exception("Failed to set PDU mode: $response"))
            }
            
            // Build PDU
            val pdu = buildSmsPdu(message)
            val pduLength = (pdu.length / 2) - 1  // Length of TPDU in bytes
            
            Log.d(TAG, "Sending SMS: length=$pduLength, PDU=$pdu")
            
            // Send SMS command
            response = sendAtCommand(device, "AT+CMGS=$pduLength")
            if (!response.contains(">")) {
                return@withContext Result.failure(Exception("Modem not ready: $response"))
            }
            
            // Send PDU (terminated with Ctrl+Z = 0x1A)
            response = sendAtCommand(device, "$pdu\u001A")
            
            if (response.contains("OK") || response.contains("+CMGS:")) {
                // Extract message reference if available
                val messageRef = response.lines()
                    .firstOrNull { it.startsWith("+CMGS:") }
                    ?.substringAfter("+CMGS:")
                    ?.trim()
                
                Log.i(TAG, "SMS sent successfully via AT: ref=$messageRef")
                Result.success(messageRef ?: "SUCCESS")
            } else {
                Result.failure(Exception("Send failed: $response"))
            }
            
        } catch (e: Exception) {
            Log.e(TAG, "AT command send failed", e)
            Result.failure(e)
        }
    }
    
    /**
     * Build SMS PDU (Protocol Data Unit)
     * Format: SMSC + SMS-SUBMIT
     */
    private fun buildSmsPdu(message: Message): String {
        val destination = message.destination.replace("+", "").replace("-", "").replace(" ", "")
        
        // SMSC (Service Center) - use default (00 = use device default)
        val smsc = "00"
        
        // SMS-SUBMIT header
        val pduType = when (message.type) {
            MessageType.SMS_FLASH -> 0x10  // Class 0 (Flash)
            MessageType.SMS_SILENT -> 0x40  // Type 0 (Silent) - PID=0x40
            else -> 0x11  // Standard with validity period
        }
        
        val pduHeader = String.format("%02X", pduType)
        
        // Message reference (let modem set)
        val messageRef = "00"
        
        // Destination address
        val destLength = destination.length
        val destType = if (destination.startsWith("00")) "91" else "81"  // International or national
        val destAddress = swapNibbles(destination)
        val destPdu = String.format("%02X%s%s", destLength, destType, destAddress)
        
        // Protocol Identifier
        val pid = when (message.type) {
            MessageType.SMS_SILENT -> "40"  // Silent SMS (Type 0)
            else -> "00"  // Normal SMS
        }
        
        // Data Coding Scheme
        val dcs = when {
            message.type == MessageType.SMS_FLASH -> "10"  // Class 0 (Flash)
            message.type == MessageType.SMS_BINARY -> "04"  // 8-bit
            message.body?.any { it.code > 127 } == true -> "08"  // UCS-2
            else -> "00"  // GSM 7-bit
        }
        
        // Validity Period (relative, 24 hours = 0xA7)
        val vp = "A7"
        
        // User Data
        val (udl, userData) = encodeUserData(message.body ?: "", dcs)
        
        // Combine all parts
        return smsc + pduHeader + messageRef + destPdu + pid + dcs + vp + udl + userData
    }
    
    /**
     * Encode user data based on DCS
     */
    private fun encodeUserData(text: String, dcs: String): Pair<String, String> {
        return when (dcs) {
            "00" -> {
                // GSM 7-bit
                val encoded = encodeGsm7Bit(text)
                val udl = String.format("%02X", text.length)
                Pair(udl, encoded)
            }
            "08" -> {
                // UCS-2
                val encoded = text.map { String.format("%04X", it.code) }.joinToString("")
                val udl = String.format("%02X", encoded.length / 2)
                Pair(udl, encoded)
            }
            "04" -> {
                // 8-bit binary
                val encoded = text.toByteArray().joinToString("") { String.format("%02X", it) }
                val udl = String.format("%02X", text.length)
                Pair(udl, encoded)
            }
            else -> {
                val udl = String.format("%02X", text.length)
                Pair(udl, text.map { String.format("%02X", it.code) }.joinToString(""))
            }
        }
    }
    
    /**
     * Encode text as GSM 7-bit
     */
    private fun encodeGsm7Bit(text: String): String {
        // Simplified GSM 7-bit encoding
        // In production, use proper bit packing
        return text.toByteArray().joinToString("") { String.format("%02X", it) }
    }
    
    /**
     * Swap nibbles for BCD encoding of phone numbers
     */
    private fun swapNibbles(number: String): String {
        val padded = if (number.length % 2 != 0) number + "F" else number
        return padded.chunked(2) { "${it[1]}${it[0]}" }.joinToString("")
    }
    
    /**
     * Send AT command to modem device
     */
    private suspend fun sendAtCommand(devicePath: String, command: String): String = withContext(Dispatchers.IO) {
        try {
            // Open device with root
            val result = rootManager.executeRootCommand("""
                stty -F $devicePath 115200 cs8 -cstopb -parenb
                echo -ne "$command\r\n" > $devicePath
                timeout 3 cat $devicePath
            """.trimIndent())
            
            if (result.success) {
                Log.d(TAG, "AT Command: $command -> ${result.output}")
                result.output
            } else {
                Log.e(TAG, "AT Command failed: ${result.error}")
                "ERROR: ${result.error}"
            }
        } catch (e: Exception) {
            Log.e(TAG, "AT command exception", e)
            "ERROR: ${e.message}"
        }
    }
    
    /**
     * Get Service Center Address
     */
    suspend fun getServiceCenterAddress(): String? = withContext(Dispatchers.IO) {
        val device = modemDevice ?: return@withContext null
        
        try {
            val response = sendAtCommand(device, "AT+CSCA?")
            // Parse response: +CSCA: "+1234567890",145
            response.lines()
                .firstOrNull { it.startsWith("+CSCA:") }
                ?.substringAfter("\"")
                ?.substringBefore("\"")
        } catch (e: Exception) {
            Log.e(TAG, "Failed to get SMSC", e)
            null
        }
    }
    
    /**
     * Set Service Center Address
     */
    suspend fun setServiceCenterAddress(smsc: String): Boolean = withContext(Dispatchers.IO) {
        val device = modemDevice ?: return@withContext false
        
        try {
            val response = sendAtCommand(device, "AT+CSCA=\"$smsc\"")
            response.contains("OK")
        } catch (e: Exception) {
            Log.e(TAG, "Failed to set SMSC", e)
            false
        }
    }
    
    /**
     * Check if AT interface is ready
     */
    fun isReady(): Boolean = modemDevice != null
    
    /**
     * Get current modem device path
     */
    fun getModemDevice(): String? = modemDevice
}
