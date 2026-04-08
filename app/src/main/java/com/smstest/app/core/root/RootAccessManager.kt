package com.smstest.app.core.root

import android.util.Log
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.withContext
import java.io.BufferedReader
import java.io.DataOutputStream
import java.io.File
import java.io.InputStreamReader

object RootAccessManager {
    private const val TAG = "RootAccessManager"

    private val _rootAvailable = MutableStateFlow<Boolean?>(null)
    val rootAvailable: StateFlow<Boolean?> = _rootAvailable.asStateFlow()

    private val _activityLog = MutableStateFlow<List<RootActivity>>(emptyList())
    val activityLog: StateFlow<List<RootActivity>> = _activityLog.asStateFlow()

    fun logActivity(message: String, type: RootActivityType) {
        val entry = RootActivity(System.currentTimeMillis(), message, type)
        _activityLog.update { it + entry }
        Log.d(TAG, "Activity: $message ($type)")
    }

    suspend fun isRootAvailable(): Boolean = withContext(Dispatchers.IO) {
        try {
            val suPaths = listOf(
                "/system/bin/su",
                "/system/xbin/su",
                "/sbin/su",
                "/system/su",
                "/data/local/xbin/su",
                "/data/local/bin/su",
                "/data/local/su"
            )
            val suExists = suPaths.any { File(it).exists() }
            if (!suExists) {
                _rootAvailable.value = false
                return@withContext false
            }

            val process = Runtime.getRuntime().exec("su -c id")
            val reader = BufferedReader(InputStreamReader(process.inputStream))
            val output = reader.readText()
            val exitCode = process.waitFor()
            reader.close()

            val hasRoot = exitCode == 0 && output.contains("uid=0")
            _rootAvailable.value = hasRoot
            hasRoot
        } catch (e: Exception) {
            Log.e(TAG, "Root check failed", e)
            _rootAvailable.value = false
            false
        }
    }

    suspend fun executeRootCommand(command: String): RootCommandResult = withContext(Dispatchers.IO) {
        try {
            val process = Runtime.getRuntime().exec("su")
            val outputStream = DataOutputStream(process.outputStream)
            outputStream.writeBytes("$command\n")
            outputStream.writeBytes("exit\n")
            outputStream.flush()

            val stdout = BufferedReader(InputStreamReader(process.inputStream)).readText()
            val stderr = BufferedReader(InputStreamReader(process.errorStream)).readText()
            val exitCode = process.waitFor()
            outputStream.close()

            RootCommandResult(
                success = exitCode == 0,
                output = stdout,
                error = stderr,
                exitCode = exitCode
            )
        } catch (e: Exception) {
            RootCommandResult(
                success = false,
                output = "",
                error = e.message ?: "Unknown error",
                exitCode = -1
            )
        }
    }

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
            if (File(path).exists()) available.add(path)
        }
        available
    }

    suspend fun checkDeviceAccess(devicePath: String): Boolean = withContext(Dispatchers.IO) {
        if (!File(devicePath).exists()) return@withContext false
        val result = executeRootCommand("test -r $devicePath && test -w $devicePath && echo OK")
        result.success && result.output.contains("OK")
    }

    suspend fun getSystemProperty(property: String): String? = withContext(Dispatchers.IO) {
        try {
            val process = Runtime.getRuntime().exec("getprop $property")
            val reader = BufferedReader(InputStreamReader(process.inputStream))
            val value = reader.readLine()?.trim()
            reader.close()
            process.waitFor()
            value?.takeIf { it.isNotEmpty() }
        } catch (e: Exception) {
            null
        }
    }

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

data class RootCommandResult(
    val success: Boolean,
    val output: String,
    val error: String,
    val exitCode: Int,
    val cancelled: Boolean = false
)

data class DeviceInfo(
    val manufacturer: String,
    val model: String,
    val device: String,
    val androidVersion: String,
    val sdkLevel: Int,
    val baseband: String
)

data class RootActivity(
    val timestamp: Long,
    val message: String,
    val type: RootActivityType
)

enum class RootActivityType {
    INFO, SUCCESS, WARNING, ERROR, DEBUG
}
