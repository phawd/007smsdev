package com.zerosms.testing.core.root

import android.util.Log
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.BufferedReader
import java.io.DataOutputStream
import java.io.File
import java.io.InputStreamReader

/**
 * Root access manager for executing privileged commands.
 * Provides detection of root availability and command execution.
 */
object RootAccessManager {
    private const val TAG = "RootAccessManager"

    /**
     * Check if root access is available on device.
     */
    suspend fun isRootAvailable(): Boolean = withContext(Dispatchers.IO) {
        try {
            // Check for su binary in common locations
            val suPaths = listOf(
                "/system/bin/su",
                "/system/xbin/su",
                "/sbin/su",
                "/system/su",
                "/data/local/xbin/su",
                "/data/local/bin/su",
                "/data/local/su"
            )
            
            // First check if any su binary exists
            val suExists = suPaths.any { File(it).exists() }
            if (!suExists) {
                Log.d(TAG, "No su binary found in common paths")
                return@withContext false
            }
            
            // Try to execute su command
            val process = Runtime.getRuntime().exec("su -c id")
            val reader = BufferedReader(InputStreamReader(process.inputStream))
            val output = reader.readText()
            val exitCode = process.waitFor()
            reader.close()
            
            val hasRoot = exitCode == 0 && output.contains("uid=0")
            Log.d(TAG, "Root check: exitCode=$exitCode, hasRoot=$hasRoot")
            hasRoot
        } catch (e: Exception) {
            Log.e(TAG, "Root check failed", e)
            false
        }
    }

    /**
     * Execute a command with root privileges.
     */
    suspend fun executeRootCommand(command: String): RootCommandResult = withContext(Dispatchers.IO) {
        try {
            Log.d(TAG, "Executing root command: $command")
            
            val process = Runtime.getRuntime().exec("su")
            val outputStream = DataOutputStream(process.outputStream)
            
            outputStream.writeBytes("$command\n")
            outputStream.writeBytes("exit\n")
            outputStream.flush()
            
            val stdout = BufferedReader(InputStreamReader(process.inputStream)).readText()
            val stderr = BufferedReader(InputStreamReader(process.errorStream)).readText()
            val exitCode = process.waitFor()
            
            outputStream.close()
            
            Log.d(TAG, "Command result: exitCode=$exitCode, stdout=${stdout.take(100)}")
            
            RootCommandResult(
                success = exitCode == 0,
                output = stdout,
                error = stderr,
                exitCode = exitCode
            )
        } catch (e: Exception) {
            Log.e(TAG, "Root command failed", e)
            RootCommandResult(
                success = false,
                output = "",
                error = e.message ?: "Unknown error",
                exitCode = -1
            )
        }
    }

    /**
     * Get available modem device ports.
     */
    suspend fun getModemPorts(): List<String> = withContext(Dispatchers.IO) {
        val candidates = listOf(
            "/dev/smd0",
            "/dev/smd11",
            "/dev/ttyUSB0",
            "/dev/ttyUSB1",
            "/dev/ttyUSB2",
            "/dev/ttyACM0",
            "/dev/ttyGS0",
            "/dev/gsmtty1",
            "/dev/gsmtty2",
            "/dev/qmi0",
            "/dev/qmi1"
        )
        
        val available = mutableListOf<String>()
        for (path in candidates) {
            if (File(path).exists()) {
                available.add(path)
                Log.d(TAG, "Found modem port: $path")
            }
        }
        
        // Also check /dev for tty* pattern
        try {
            val devDir = File("/dev")
            val ttyDevices = devDir.listFiles()?.filter { 
                it.name.startsWith("tty") && (it.name.contains("USB") || it.name.contains("ACM"))
            }?.map { it.absolutePath } ?: emptyList()
            
            for (tty in ttyDevices) {
                if (tty !in available) {
                    available.add(tty)
                    Log.d(TAG, "Found additional tty device: $tty")
                }
            }
        } catch (e: Exception) {
            Log.e(TAG, "Error scanning /dev", e)
        }
        
        available
    }

    /**
     * Check if device path is accessible with root.
     */
    suspend fun checkDeviceAccess(devicePath: String): Boolean = withContext(Dispatchers.IO) {
        try {
            if (!File(devicePath).exists()) {
                Log.d(TAG, "Device does not exist: $devicePath")
                return@withContext false
            }
            
            // Try to read device with root
            val result = executeRootCommand("test -r $devicePath && test -w $devicePath && echo OK")
            val accessible = result.success && result.output.contains("OK")
            Log.d(TAG, "Device access check for $devicePath: $accessible")
            accessible
        } catch (e: Exception) {
            Log.e(TAG, "Device access check failed", e)
            false
        }
    }

    /**
     * Get Android system property value.
     */
    suspend fun getSystemProperty(property: String): String? = withContext(Dispatchers.IO) {
        try {
            val process = Runtime.getRuntime().exec("getprop $property")
            val reader = BufferedReader(InputStreamReader(process.inputStream))
            val value = reader.readLine()?.trim()
            reader.close()
            process.waitFor()
            value?.takeIf { it.isNotEmpty() }
        } catch (e: Exception) {
            Log.e(TAG, "Failed to get property $property", e)
            null
        }
    }

    /**
     * Get device model information.
     */
    suspend fun getDeviceInfo(): DeviceInfo = withContext(Dispatchers.IO) {
        DeviceInfo(
            manufacturer = getSystemProperty("ro.product.manufacturer") ?: "Unknown",
            model = getSystemProperty("ro.product.model") ?: "Unknown",
            device = getSystemProperty("ro.product.device") ?: "Unknown",
            androidVersion = getSystemProperty("ro.build.version.release") ?: "Unknown",
            sdkLevel = getSystemProperty("ro.build.version.sdk")?.toIntOrNull() ?: 0,
            baseband = getSystemProperty("gsm.version.baseband") ?: "Unknown"
        )
    }
}

/**
 * Result of a root command execution.
 */
data class RootCommandResult(
    val success: Boolean,
    val output: String,
    val error: String,
    val exitCode: Int,
    val cancelled: Boolean = false
)

/**
 * Device information.
 */
data class DeviceInfo(
    val manufacturer: String,
    val model: String,
    val device: String,
    val androidVersion: String,
    val sdkLevel: Int,
    val baseband: String
)

/**
 * Activity log entry for root operations
 */
data class RootActivity(
    val timestamp: Long,
    val message: String,
    val type: RootActivityType
)

/**
 * Type of root activity
 */
enum class RootActivityType {
    INFO, SUCCESS, WARNING, ERROR, DEBUG
}
