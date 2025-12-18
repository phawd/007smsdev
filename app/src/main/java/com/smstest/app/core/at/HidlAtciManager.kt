package com.smstest.app.core.at

import android.util.Log
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.withContext
import java.io.BufferedReader
import java.io.InputStreamReader

/**
 * MediaTek HIDL ATCI Manager
 * 
 * Attempts to call vendor.mediatek.hardware.atci@1.0::IAtcid/default HIDL service
 * for AT command execution.
 */
class HidlAtciManager {
    companion object {
        private const val TAG = "HidlAtciManager"
        
        // HIDL service name
        private const val HIDL_SERVICE = "vendor.mediatek.hardware.atci@1.0::IAtcid/default"
    }
    
    /**
     * Try to get HIDL service info
     */
    suspend fun getHidlServiceInfo(): String? = withContext(Dispatchers.IO) {
        try {
            // Use hidl_client or get_hal_service to query HIDL
            val result = executeCommand("lshal | grep -i atci")
            Log.d(TAG, "HIDL query result: $result")
            result
        } catch (e: Exception) {
            Log.e(TAG, "Failed to query HIDL", e)
            null
        }
    }
    
    /**
     * Try to send AT command via HIDL IAtcid interface
     * 
     * MediaTek ATCI HIDL interface typically has:
     * - sendAtCmd(String cmd) -> Status
     * - getResponse() -> String
     */
    suspend fun sendAtViaHidl(atCommand: String): String = withContext(Dispatchers.IO) {
        try {
            // Attempt 1: Use cmd HAL interface (if available)
            var result = tryHalService(atCommand)
            if (result.isNotEmpty()) return@withContext result
            
            // Attempt 2: Use direct binary access to HIDL socket
            result = tryHidlSocket(atCommand)
            if (result.isNotEmpty()) return@withContext result
            
            // Attempt 3: Use atcid daemon if it has a command interface
            result = tryAtcidDaemon(atCommand)
            if (result.isNotEmpty()) return@withContext result
            
            "ERROR: No HIDL interface available"
        } catch (e: Exception) {
            Log.e(TAG, "HIDL AT command failed", e)
            "ERROR: ${e.message}"
        }
    }
    
    /**
     * Try HAL service command execution
     */
    private suspend fun tryHalService(atCmd: String): String = withContext(Dispatchers.IO) {
        try {
            // Some devices expose hal_client or service tool
            val cmd = """
                service call vendor.mediatek.hardware.atci 1 s16 "$atCmd"
            """.trimIndent()
            
            val output = executeCommand(cmd)
            Log.d(TAG, "HAL service response: $output")
            output
        } catch (e: Exception) {
            ""
        }
    }
    
    /**
     * Try direct HIDL socket access
     * /dev/socket/hwbinder for HwBinder or specific ATCI socket
     */
    private suspend fun tryHidlSocket(atCmd: String): String = withContext(Dispatchers.IO) {
        try {
            // Look for HIDL-related sockets
            val result = executeCommand("""
                ls -la /dev/socket/ | grep -E 'atci|hwbinder|binder'
            """.trimIndent())
            Log.d(TAG, "Available sockets: $result")
            
            // Try /dev/socket/adb_atci_socket (we know this exists)
            val atciSocket = "/dev/socket/adb_atci_socket"
            val echoCmd = """
                echo -ne 'AT\r\n' | nc -U $atciSocket & sleep 0.5; jobs -p | xargs kill 2>/dev/null
            """.trimIndent()
            
            val response = executeCommand(echoCmd)
            Log.d(TAG, "Socket response: $response")
            response
        } catch (e: Exception) {
            ""
        }
    }
    
    /**
     * Try atcid daemon direct interaction
     */
    private suspend fun tryAtcidDaemon(atCmd: String): String = withContext(Dispatchers.IO) {
        try {
            // Check if atcid has any CLI interface or debug port
            val pidResult = executeCommand("pidof atcid")
            Log.d(TAG, "atcid PID: $pidResult")
            
            if (pidResult.isEmpty()) {
                return@withContext ""
            }
            
            // Try to interact via /proc/[pid]/fd
            val pid = pidResult.trim().split(" ").firstOrNull() ?: return@withContext ""
            val fdResult = executeCommand("ls -la /proc/$pid/fd | grep socket")
            Log.d(TAG, "atcid file descriptors: $fdResult")
            
            ""
        } catch (e: Exception) {
            ""
        }
    }
    
    /**
     * Execute shell command
     */
    private suspend fun executeCommand(cmd: String): String = withContext(Dispatchers.IO) {
        try {
            val process = Runtime.getRuntime().exec(arrayOf("sh", "-c", cmd))
            
            val reader = BufferedReader(InputStreamReader(process.inputStream))
            val output = reader.readText()
            reader.close()
            
            val exitCode = process.waitFor()
            Log.d(TAG, "Command '$cmd' exit code: $exitCode")
            
            output
        } catch (e: Exception) {
            Log.e(TAG, "Command execution failed", e)
            ""
        }
    }
    
    /**
     * Check if HIDL service is available
     */
    suspend fun isHidlServiceAvailable(): Boolean = withContext(Dispatchers.IO) {
        try {
            val output = executeCommand("lshal | grep atci")
            output.contains("atci") || output.contains("IAtcid")
        } catch (e: Exception) {
            false
        }
    }
}
