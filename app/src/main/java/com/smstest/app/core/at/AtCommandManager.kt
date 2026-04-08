package com.smstest.app.core.at

import com.smstest.app.core.Logger
import com.smstest.app.core.device.AtCommandMethod
import com.smstest.app.core.device.ModemChipset
import com.smstest.app.core.root.RootAccessManager
import com.smstest.app.core.root.RootActivityType
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.util.Locale

/**
 * Root-backed AT command manager for modem SMS operations.
 * Supports probing/init and sending SMS in text or PDU mode.
 */
object AtCommandManager {
    private const val TAG = "AtCommandManager"
    private const val CTRL_Z = 0x1A.toByte()

    private var initializedDevice: String? = null
    private var initializedMethod: AtCommandMethod = AtCommandMethod.UNKNOWN
    private var lastScan: List<AtCapabilityScanResult> = emptyList()

    data class BuiltPdu(
        val pdu: String,
        val tpduLength: Int,
        val pid: Int,
        val dcs: Int,
        val encoding: String
    )

    private data class AtSessionResult(
        val success: Boolean,
        val response: String,
        val stderr: String,
        val exitCode: Int
    )

    fun isInitialized(): Boolean = initializedDevice != null

    fun getInitializedDevice(): String? = initializedDevice

    fun getInitializedMethod(): AtCommandMethod = initializedMethod

    fun getLastCapabilityScan(): List<AtCapabilityScanResult> = lastScan

    suspend fun scanCapabilities(preferredPaths: List<String> = emptyList()): List<AtCapabilityScanResult> =
        withContext(Dispatchers.IO) {
            val candidates = buildCandidateDeviceList(preferredPaths)
            val scanResults = mutableListOf<AtCapabilityScanResult>()
            val rootAvailable = RootAccessManager.isRootAvailable()

            if (!rootAvailable) {
                scanResults.addAll(
                    candidates.map { (path, chipset) ->
                        AtCapabilityScanResult(
                            devicePath = path,
                            chipset = chipset,
                            exists = false,
                            accessible = false,
                            responded = false,
                            responseSnippet = "Root not available"
                        )
                    }
                )
                lastScan = scanResults
                return@withContext scanResults
            }

            for ((path, chipset) in candidates) {
                val escapedPath = escapeShellSingle(path)
                val existsResult = RootAccessManager.executeRootCommand("test -e '$escapedPath' && echo EXISTS || echo MISSING")
                val exists = existsResult.output.contains("EXISTS")

                if (!exists) {
                    scanResults.add(
                        AtCapabilityScanResult(
                            devicePath = path,
                            chipset = chipset,
                            exists = false,
                            accessible = false,
                            responded = false,
                            responseSnippet = "Missing"
                        )
                    )
                    continue
                }

                val accessResult = RootAccessManager.executeRootCommand(
                    "test -r '$escapedPath' -a -w '$escapedPath' && echo ACCESS || (chmod 666 '$escapedPath' >/dev/null 2>&1 && test -r '$escapedPath' -a -w '$escapedPath' && echo ACCESS || echo DENY)"
                )
                val accessible = accessResult.output.contains("ACCESS")

                if (!accessible) {
                    scanResults.add(
                        AtCapabilityScanResult(
                            devicePath = path,
                            chipset = chipset,
                            exists = true,
                            accessible = false,
                            responded = false,
                            responseSnippet = "Permission denied"
                        )
                    )
                    continue
                }

                val probeResult = runAtSequence(
                    devicePath = path,
                    writes = listOf(
                        atLine("AT"),
                        atLine("ATE0"),
                        atLine("AT+CMEE=1")
                    ),
                    readTimeoutSec = 2
                )
                val snippet = probeResult.response.take(120).ifBlank { probeResult.stderr.take(120) }
                val responded = probeResult.response.contains("OK", ignoreCase = true)

                scanResults.add(
                    AtCapabilityScanResult(
                        devicePath = path,
                        chipset = chipset,
                        exists = true,
                        accessible = true,
                        responded = responded,
                        responseSnippet = if (snippet.isNotBlank()) snippet else "No response"
                    )
                )
            }

            lastScan = scanResults
            scanResults
        }

    suspend fun probeDevices(): List<String> = withContext(Dispatchers.IO) {
        val scanResults = scanCapabilities()
        val responsive = scanResults.filter { it.responded }.map { it.devicePath }
        if (responsive.isNotEmpty()) responsive else scanResults.filter { it.accessible }.map { it.devicePath }
    }

    suspend fun initializeAtOnDevice(
        devicePath: String,
        method: AtCommandMethod = AtCommandMethod.UNKNOWN
    ): Boolean = withContext(Dispatchers.IO) {
        val initResult = runAtSequence(
            devicePath = devicePath,
            writes = listOf(
                atLine("AT"),
                atLine("ATE0"),
                atLine("AT+CMEE=1"),
                atLine("AT+CMGF=0")
            ),
            readTimeoutSec = 3
        )
        val ok = initResult.response.contains("OK", ignoreCase = true) &&
            !initResult.response.contains("ERROR", ignoreCase = true)

        if (ok) {
            initializedDevice = devicePath
            initializedMethod = method
            RootAccessManager.logActivity("AT initialized on $devicePath", RootActivityType.SUCCESS)
            Logger.i(TAG, "AT initialized on $devicePath")
        } else {
            Logger.w(TAG, "AT init failed on $devicePath (exit=${initResult.exitCode}): ${initResult.response.ifBlank { initResult.stderr }}")
        }

        ok
    }

    suspend fun sendSmsText(destination: String, body: String): Boolean = withContext(Dispatchers.IO) {
        val device = initializedDevice ?: return@withContext false
        val normalizedDestination = normalizeDestination(destination)

        val sendResult = runAtSequence(
            devicePath = device,
            writes = listOf(
                atLine("AT"),
                atLine("AT+CMEE=1"),
                atLine("AT+CMGF=1"),
                atLine("AT+CMGS=\"$normalizedDestination\""),
                bodyWithCtrlZ(body)
            ),
            readTimeoutSec = 10
        )

        val success = sendResult.response.contains("OK", ignoreCase = true) &&
            !sendResult.response.contains("ERROR", ignoreCase = true)

        if (!success) {
            Logger.w(TAG, "AT text send failed: ${sendResult.response.ifBlank { sendResult.stderr }}")
        }
        success
    }

    suspend fun sendSmsPdu(pdu: String, tpduLen: Int): Boolean = withContext(Dispatchers.IO) {
        val device = initializedDevice ?: return@withContext false
        val normalizedPdu = pdu.uppercase(Locale.US).trim()

        val sendResult = runAtSequence(
            devicePath = device,
            writes = listOf(
                atLine("AT"),
                atLine("AT+CMEE=1"),
                atLine("AT+CMGF=0"),
                atLine("AT+CMGS=$tpduLen"),
                pduWithCtrlZ(normalizedPdu)
            ),
            readTimeoutSec = 12
        )

        val success = sendResult.response.contains("OK", ignoreCase = true) &&
            !sendResult.response.contains("ERROR", ignoreCase = true)

        if (!success) {
            Logger.w(TAG, "AT PDU send failed: ${sendResult.response.ifBlank { sendResult.stderr }}")
        }
        success
    }

    fun buildFlashSmsPdu(destination: String, body: String): BuiltPdu {
        val unicode = body.any { it.code > 0x7F }
        val pid = 0x00
        val dcs = if (unicode) 0x18 else 0x10
        return buildSubmitPdu(destination, body, pid, dcs, unicode)
    }

    fun buildSilentSmsPdu(destination: String, body: String): BuiltPdu {
        val unicode = body.any { it.code > 0x7F }
        val pid = 0x40
        val dcs = if (unicode) 0x08 else 0x00
        return buildSubmitPdu(destination, body, pid, dcs, unicode)
    }

    fun buildBinarySmsPdu(destination: String, payload: ByteArray, destinationPort: Int, sourcePort: Int = 0): BuiltPdu {
        val normalized = normalizeDestination(destination)
        val number = normalized.removePrefix("+").filter { it.isDigit() }
        val toa = if (normalized.startsWith("+")) "91" else "81"
        val addrDigits = number.length
        val addrSemi = encodePhoneNumber(number)

        val udh = byteArrayOf(
            0x06.toByte(),
            0x05.toByte(), 0x04.toByte(),
            ((destinationPort ushr 8) and 0xFF).toByte(),
            (destinationPort and 0xFF).toByte(),
            ((sourcePort ushr 8) and 0xFF).toByte(),
            (sourcePort and 0xFF).toByte()
        )
        val userData = udh + payload
        val userDataHex = bytesToHex(userData)

        val tpdu = buildString {
            append("41")
            append("00")
            append("%02X".format(addrDigits))
            append(toa)
            append(addrSemi)
            append("00")
            append("04")
            append("%02X".format(userData.size))
            append(userDataHex)
        }
        val pdu = "00$tpdu"
        return BuiltPdu(pdu, pdu.length / 2 - 1, 0x00, 0x04, "8BIT_UDH_PORT")
    }

    private fun buildSubmitPdu(destination: String, body: String, pid: Int, dcs: Int, forceUnicode: Boolean): BuiltPdu {
        val normalized = normalizeDestination(destination)
        val number = normalized.removePrefix("+").filter { it.isDigit() }
        val toa = if (normalized.startsWith("+")) "91" else "81"
        val addrDigits = number.length
        val addrSemi = encodePhoneNumber(number)

        val userData = if (forceUnicode || dcs == 0x08 || dcs == 0x18) {
            body.toByteArray(Charsets.UTF_16BE)
        } else {
            body.toByteArray(Charsets.US_ASCII)
        }

        val tpdu = buildString {
            append("01")
            append("00")
            append("%02X".format(addrDigits))
            append(toa)
            append(addrSemi)
            append("%02X".format(pid and 0xFF))
            append("%02X".format(dcs and 0xFF))
            append("%02X".format(userData.size and 0xFF))
            append(bytesToHex(userData))
        }

        val pdu = "00$tpdu"
        return BuiltPdu(
            pdu = pdu,
            tpduLength = pdu.length / 2 - 1,
            pid = pid,
            dcs = dcs,
            encoding = if (forceUnicode || dcs == 0x08 || dcs == 0x18) "UCS2" else "ASCII_8BIT"
        )
    }

    private suspend fun runAtSequence(devicePath: String, writes: List<ByteArray>, readTimeoutSec: Int): AtSessionResult =
        withContext(Dispatchers.IO) {
            val writeScript = writes.joinToString("\n") { bytes ->
                val escaped = bytesToEscapedHex(bytes)
                "printf '%b' '$escaped' >&3\nsleep 1"
            }
            val escapedDevice = escapeShellSingle(devicePath)
            val command = """
                DEVICE='$escapedDevice'
                if [ ! -e "$DEVICE" ]; then
                  echo '__NO_DEVICE__'
                  exit 20
                fi
                if [ ! -r "$DEVICE" ] || [ ! -w "$DEVICE" ]; then
                  chmod 666 "$DEVICE" >/dev/null 2>&1 || true
                fi
                exec 3<>"$DEVICE" || { echo '__OPEN_FAILED__'; exit 21; }
                $writeScript
                if command -v timeout >/dev/null 2>&1; then
                  timeout $readTimeoutSec cat <&3 2>/dev/null | tr -d '\000' | head -c 2048
                fi
                exec 3>&-
                exec 3<&-
            """.trimIndent()

            val result = RootAccessManager.executeRootCommand(command)
            val success = result.success || result.exitCode == 124
            AtSessionResult(success, result.output.trim(), result.error.trim(), result.exitCode)
        }

    private fun buildCandidateDeviceList(preferredPaths: List<String>): List<Pair<String, ModemChipset>> {
        val known = linkedMapOf<String, ModemChipset>()
        preferredPaths.forEach { known[it] = ModemChipset.UNKNOWN }
        val staticCandidates = mapOf(
            "/dev/smd0" to ModemChipset.QUALCOMM_GENERIC,
            "/dev/smd11" to ModemChipset.QUALCOMM_GENERIC,
            "/dev/ttyHS0" to ModemChipset.QUALCOMM_SDM,
            "/dev/ttyHS1" to ModemChipset.QUALCOMM_SDM,
            "/dev/ttyUSB0" to ModemChipset.UNKNOWN,
            "/dev/ttyUSB1" to ModemChipset.UNKNOWN,
            "/dev/ttyUSB2" to ModemChipset.UNKNOWN,
            "/dev/ttyACM0" to ModemChipset.UNKNOWN,
            "/dev/ttyACM1" to ModemChipset.UNKNOWN,
            "/dev/radio/pttycmd1" to ModemChipset.MEDIATEK_GENERIC,
            "/dev/radio/pttycmd2" to ModemChipset.MEDIATEK_GENERIC,
            "/dev/ttyMT0" to ModemChipset.MEDIATEK_GENERIC,
            "/dev/ttyCMIPC0" to ModemChipset.MEDIATEK_GENERIC,
            "/dev/umts_ipc0" to ModemChipset.SAMSUNG_EXYNOS,
            "/dev/appvcom" to ModemChipset.HISILICON_KIRIN,
            "/dev/gsmtty1" to ModemChipset.INTEL_XMM,
            "/dev/stty_lte1" to ModemChipset.SPREADTRUM,
            "/dev/wwan0at" to ModemChipset.QUALCOMM_SDM,
            "/dev/wwan1at" to ModemChipset.QUALCOMM_SDM
        )
        staticCandidates.forEach { (path, chipset) -> known.putIfAbsent(path, chipset) }
        return known.entries.map { it.key to it.value }
    }

    private fun atLine(command: String): ByteArray = "$command\r".toByteArray(Charsets.US_ASCII)
    private fun bodyWithCtrlZ(body: String): ByteArray = body.toByteArray(Charsets.UTF_8) + byteArrayOf(CTRL_Z)
    private fun pduWithCtrlZ(pduHex: String): ByteArray = pduHex.toByteArray(Charsets.US_ASCII) + byteArrayOf(CTRL_Z)
    private fun bytesToEscapedHex(bytes: ByteArray): String = bytes.joinToString("") { "\\x%02X".format(it.toInt() and 0xFF) }
    private fun bytesToHex(bytes: ByteArray): String = bytes.joinToString("") { "%02X".format(it.toInt() and 0xFF) }

    private fun encodePhoneNumber(number: String): String {
        val normalized = number.filter { it.isDigit() }
        val padded = if (normalized.length % 2 == 0) normalized else "${normalized}F"
        val swapped = StringBuilder()
        var i = 0
        while (i < padded.length) {
            swapped.append(padded[i + 1]).append(padded[i])
            i += 2
        }
        return swapped.toString()
    }

    private fun normalizeDestination(destination: String): String = destination.trim().filter { it.isDigit() || it == '+' }
    private fun escapeShellSingle(value: String): String = value.replace("'", "'\"'\"'")
}
