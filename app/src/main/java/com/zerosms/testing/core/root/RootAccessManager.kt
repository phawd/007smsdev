package com.zerosms.testing.core.root

import android.util.Log
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.BufferedReader
import java.io.DataOutputStream
import java.io.InputStreamReader

/**
 * Root Access Manager
 * 
 * Provides utilities for detecting and using root access on Android devices.
 * Required for AT command execution and low-level modem operations.
 */
class RootAccessManager {
    
    private val TAG = "RootAccessManager"
    
    /**
     * Check if device has root access
     * Tests multiple methods to detect root
     */
    suspend fun isRootAvailable(): Boolean = withContext(Dispatchers.IO) {
        try {
            // Method 1: Try to execute 'su' command
            val process = Runtime.getRuntime().exec("su")
            val outputStream = DataOutputStream(process.outputStream)
            outputStream.writeBytes("id\n")
            outputStream.writeBytes("exit\n")
            outputStream.flush()
            
            val exitCode = process.waitFor()
            val reader = BufferedReader(InputStreamReader(process.inputStream))
            val output = reader.readText()
            
            Log.d(TAG, "Root check: exitCode=$exitCode, output=$output")
            
            // Check if we got uid=0 (root)
            return@withContext exitCode == 0 && output.contains("uid=0")
        } catch (e: Exception) {
            Log.e(TAG, "Root check failed", e)
            return@withContext false
        }
    }
    
    /**
     * Execute command as root
     * @param command The command to execute
     * @return Result containing output and error
     */
    suspend fun executeRootCommand(command: String): RootCommandResult = withContext(Dispatchers.IO) {
        try {
            val process = Runtime.getRuntime().exec("su")
            val outputStream = DataOutputStream(process.outputStream)
            
            // Write command
            outputStream.writeBytes("$command\n")
            outputStream.writeBytes("exit\n")
            outputStream.flush()
            
            // Read output
            val reader = BufferedReader(InputStreamReader(process.inputStream))
            val errorReader = BufferedReader(InputStreamReader(process.errorStream))
            
            val output = StringBuilder()
            val error = StringBuilder()
            
            reader.forEachLine { output.append(it).append("\n") }
            errorReader.forEachLine { error.append(it).append("\n") }
            
            val exitCode = process.waitFor()
            
            RootCommandResult(
                success = exitCode == 0,
                output = output.toString(),
                error = error.toString(),
                exitCode = exitCode
            )
        } catch (e: Exception) {
            Log.e(TAG, "Failed to execute root command: $command", e)
            RootCommandResult(
                success = false,
                output = "",
                error = e.message ?: "Unknown error",
                exitCode = -1
            )
        }
    }
    
    /**
     * Get list of serial ports that might be modem interfaces
     * Common paths: /dev/smd0, /dev/smd11, /dev/ttyUSB0, /dev/ttyACM0
     */
    suspend fun getModemPorts(): List<String> = withContext(Dispatchers.IO) {
        val result = executeRootCommand("ls -la /dev/smd* /dev/tty* 2>/dev/null")
        if (result.success) {
            result.output.lines()
                .filter { it.contains("/dev/") }
                .mapNotNull { line ->
                    // Extract device path from ls output
                    val parts = line.split(" ")
                    parts.lastOrNull()?.takeIf { it.startsWith("/dev/") }
                }
        } else {
            emptyList()
        }
    }
    
    /**
     * Check if a specific device file exists and is accessible
     */
    suspend fun checkDeviceAccess(devicePath: String): Boolean = withContext(Dispatchers.IO) {
        val result = executeRootCommand("test -e $devicePath && echo 'exists'")
        result.success && result.output.contains("exists")
    }
    
    /**
     * Get system property (requires root for some properties)
     */
    suspend fun getSystemProperty(property: String): String? = withContext(Dispatchers.IO) {
        val result = executeRootCommand("getprop $property")
        if (result.success) result.output.trim() else null
    }
}

/**
 * Result of root command execution
 */
data class RootCommandResult(
    val success: Boolean,
    val output: String,
    val error: String,
    val exitCode: Int
)
