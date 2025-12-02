package com.zerosms.testing.core.at

import android.util.Log
import com.zerosms.testing.core.root.RootAccessManager
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.IOException

/**
 * Direct MIPC Device Manager
 * 
 * MediaTek uses Internal Protocol Communication (MIPC) through /dev/ttyCMIPC* devices.
 * These are character devices that communicate directly with the modem.
 */
class MipcDeviceManager(private val rootManager: RootAccessManager) {
    companion object {
        private const val TAG = "MipcDeviceManager"
        
        // MediaTek MIPC devices (major 496)
        private val MIPC_DEVICES = (0..9).map { "/dev/ttyCMIPC$it" }
        
        // MIPC command header bytes
        private const val MIPC_START_BYTE = 0xA0.toByte()
        private const val MIPC_END_BYTE = 0xA1.toByte()
    }
    
    private var activeDevice: String? = null
    private var inputStream: FileInputStream? = null
    private var outputStream: FileOutputStream? = null
    
    /**
     * Initialize MIPC communication
     * Open first available MIPC device
     */
    suspend fun initialize(): Boolean = withContext(Dispatchers.IO) {
        try {
            // Try to find and open a working MIPC device as root
            for (device in MIPC_DEVICES) {
                Log.d(TAG, "Trying MIPC device: $device")
                
                if (tryOpenDevice(device)) {
                    activeDevice = device
                    Log.i(TAG, "Successfully opened MIPC device: $device")
                    return@withContext true
                }
            }
            
            Log.e(TAG, "No working MIPC device found")
            return@withContext false
        } catch (e: Exception) {
            Log.e(TAG, "MIPC initialization failed", e)
            return@withContext false
        }
    }
    
    /**
     * Try to open a device
     */
    private suspend fun tryOpenDevice(device: String): Boolean = withContext(Dispatchers.IO) {
        try {
            // Root should allow us to open the device
            val cmd = """
                exec 3<>$device && echo "OK" && exec 3>&- && exec 3<&-
            """.trimIndent()
            
            val result = rootManager.executeRootCommand(cmd)
            result.success && result.output.contains("OK")
        } catch (e: Exception) {
            Log.e(TAG, "Failed to open $device", e)
            false
        }
    }
    
    /**
     * Send MIPC command
     * MIPC format: [0xA0] [LEN_H] [LEN_L] [CMD_ID] [DATA] [CHECKSUM] [0xA1]
     */
    suspend fun sendMipcCommand(commandId: Int, data: ByteArray = byteArrayOf()): ByteArray? = withContext(Dispatchers.IO) {
        try {
            val device = activeDevice ?: return@withContext null
            
            // Build MIPC frame
            val frame = buildMipcFrame(commandId, data)
            Log.d(TAG, "Sending MIPC command (${frame.size} bytes): ${frame.joinToString(" ") { "%02X".format(it) }}")
            
            // Send via root command
            val hexFrame = frame.joinToString(" ") { "\\x%02X".format(it) }
            val cmd = "printf '$hexFrame' > $device"
            
            val result = rootManager.executeRootCommand(cmd)
            if (!result.success) {
                Log.e(TAG, "Failed to send MIPC: ${result.error}")
                return@withContext null
            }
            
            // Try to read response
            readMipcResponse(device)
        } catch (e: Exception) {
            Log.e(TAG, "MIPC send failed", e)
            null
        }
    }
    
    /**
     * Build MIPC frame
     */
    private fun buildMipcFrame(commandId: Int, data: ByteArray): ByteArray {
        val length = 2 + data.size + 1  // CMD_ID (2) + DATA + CHECKSUM (1)
        val lengthH = (length shr 8).toByte()
        val lengthL = (length and 0xFF).toByte()
        
        val cmdIdH = (commandId shr 8).toByte()
        val cmdIdL = (commandId and 0xFF).toByte()
        
        // Calculate checksum
        val checksumData = byteArrayOf(cmdIdH, cmdIdL) + data
        var checksum = 0
        for (b in checksumData) {
            checksum = (checksum + (b.toInt() and 0xFF)) and 0xFF
        }
        
        // Build frame: [0xA0] [LEN_H] [LEN_L] [CMD_ID_H] [CMD_ID_L] [DATA] [CHECKSUM] [0xA1]
        return byteArrayOf(MIPC_START_BYTE, lengthH, lengthL, cmdIdH, cmdIdL) +
                data +
                byteArrayOf(checksum.toByte(), MIPC_END_BYTE)
    }
    
    /**
     * Read MIPC response
     */
    private suspend fun readMipcResponse(device: String): ByteArray? = withContext(Dispatchers.IO) {
        try {
            val cmd = "timeout 1 cat $device | xxd -p | head -c 100"
            val result = rootManager.executeRootCommand(cmd)
            
            if (result.success && result.output.isNotEmpty()) {
                Log.d(TAG, "MIPC response (hex): ${result.output}")
                // Parse hex response...
                byteArrayOf()
            } else {
                null
            }
        } catch (e: Exception) {
            Log.e(TAG, "Failed to read MIPC response", e)
            null
        }
    }
    
    /**
     * Close MIPC device
     */
    suspend fun close() = withContext(Dispatchers.IO) {
        try {
            inputStream?.close()
            outputStream?.close()
            activeDevice = null
        } catch (e: Exception) {
            Log.e(TAG, "Error closing device", e)
        }
    }
    
    /**
     * Send AT command via MIPC
     * Some MediaTek modems route AT commands through MIPC
     */
    suspend fun sendAtCommandViaMipc(atCommand: String): String? = withContext(Dispatchers.IO) {
        try {
            // This depends on the specific MIPC command ID for AT forwarding
            // Common IDs: 0xF001 for AT commands on some devices
            val atCommandBytes = "$atCommand\r".toByteArray()
            val response = sendMipcCommand(0xF001, atCommandBytes)
            
            if (response != null) {
                String(response).trim()
            } else {
                null
            }
        } catch (e: Exception) {
            Log.e(TAG, "AT via MIPC failed", e)
            null
        }
    }
}
