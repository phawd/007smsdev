package com.smstest.app.core.sms

import android.content.Context
import android.telephony.SmsManager
import android.util.Log
import android.os.Build
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch

object FlashSmsUtil {
    private const val TAG = "FlashSmsUtil"

    fun trySendFlash(context: Context, destination: String, message: String): Boolean {
        // Try root + AT path first
        val rootOk = isRootAvailable()
        if (rootOk) {
            val candidates = listOf(
                "/dev/ttyUSB0", "/dev/ttyUSB1",
                "/dev/ttyACM0", "/dev/ttyACM1",
                "/dev/radio/pttycmd1", "/dev/radio/pttycmd2",
                "/dev/at_mdm0", "/dev/at_mdm1"
            )
            for (dev in candidates) {
                val ok = sendFlashViaAt(dev, destination, message)
                if (ok) {
                    Log.i(TAG, "Flash SMS sent via AT on $dev to $destination")
                    return true
                }
            }
        } else {
            Log.w(TAG, "Root not available; skipping AT path")
        }
        // Fallback 1: Try binary/data message to port 0 (best-effort to signal special class)
        val dataOk = trySendFlashViaData(destination, message)
        if (dataOk) {
            Log.i(TAG, "Flash SMS sent via dataMessage to port 0 to $destination (best-effort)")
            return true
        }

        // Final fallback: standard API (may not enforce class 0)
        return try {
            val sms = SmsManager.getDefault()
            sms.sendTextMessage(destination, null, message, null, null)
            Log.i(TAG, "Fallback standard SMS sent to $destination (not class 0)")
            true
        } catch (e: Throwable) {
            Log.e(TAG, "Fallback SMS send failed", e)
            false
        }
    }

    private fun trySendFlashViaData(destination: String, message: String): Boolean {
        return try {
            val sms = SmsManager.getDefault()
            // Port 0 is commonly used for WAP push; using 0 as a best-effort port to deliver binary
            val port = 0
            val payload: ByteArray = if (message.any { it.code > 0x7F }) {
                // UCS-2 / UTF-16BE for unicode
                message.toByteArray(Charsets.UTF_16BE)
            } else {
                // ASCII/GSM7 best-effort
                message.toByteArray(Charsets.US_ASCII)
            }
            sms.sendDataMessage(destination, null, port.toShort(), payload, null, null)
            true
        } catch (e: Throwable) {
            Log.w(TAG, "sendDataMessage fallback failed", e)
            false
        }
    }

    private fun isRootAvailable(): Boolean = try {
        val proc = Runtime.getRuntime().exec(arrayOf("su", "-c", "id"))
        val out = proc.inputStream.bufferedReader().readText()
        out.contains("uid=0")
    } catch (e: Throwable) { false }

    private fun sendFlashViaAt(dev: String, destination: String, message: String): Boolean {
        fun sh(cmd: String): Boolean = try {
            Runtime.getRuntime().exec(arrayOf("su", "-c", cmd)).waitFor() == 0
        } catch (e: Throwable) { false }
        val ok1 = sh("echo -e 'AT\\r' > $dev")
        val ok2 = sh("echo -e 'AT+CMGF=1\\r' > $dev")
        val ok3 = sh("echo -e 'AT+CSMP=17,167,0,16\\r' > $dev")
        val ok4 = sh("echo -e 'AT+CMGS=\"$destination\"\\r' > $dev")
        val ok5 = sh("echo -e '${message}\\x1A' > $dev")
        return ok1 && ok2 && ok3 && ok4 && ok5
    }
}
