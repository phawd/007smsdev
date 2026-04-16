package com.smstest.app.core.sms

import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.telephony.SmsManager
import android.telephony.SubscriptionManager
import android.util.Log
import com.smstest.app.core.Logger
import com.smstest.app.core.at.AtCommandManager
import com.smstest.app.core.model.DeliveryStatus
import com.smstest.app.core.model.Message
import com.smstest.app.core.model.MessageClass
import com.smstest.app.core.model.MessageType
import com.smstest.app.core.model.SmsEncoding
import com.smstest.app.core.root.RootAccessManager
import com.smstest.app.core.root.RootActivityType
import com.smstest.app.core.tracking.MessageTracker
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.withContext

class SmsManagerWrapper(private val context: Context) {
    private val TAG = "SmsManagerWrapper"
    private var atCommandsAvailable = false

    private val smsManager: SmsManager = context.getSystemService(SmsManager::class.java)
    private val _messageStatus = MutableStateFlow<Map<String, DeliveryStatus>>(emptyMap())
    val messageStatus: Flow<Map<String, DeliveryStatus>> = _messageStatus.asStateFlow()
    private val _lastSendReport = MutableStateFlow<SmsSendReport?>(null)
    val lastSendReport: StateFlow<SmsSendReport?> = _lastSendReport.asStateFlow()

    companion object {
        const val SMS_MAX_LENGTH_GSM = 160
        const val SMS_MAX_LENGTH_UNICODE = 70
        const val SMS_CONCAT_MAX_LENGTH_GSM = 153
        const val SMS_CONCAT_MAX_LENGTH_UNICODE = 67

        const val ACTION_SMS_SENT = "com.smstest.app.SMS_SENT"
        const val ACTION_SMS_DELIVERED = "com.smstest.app.SMS_DELIVERED"
    }

    private data class SendExecution(
        val result: Result<String>,
        val route: SmsRoute,
        val usedRoot: Boolean,
        val usedAt: Boolean,
        val protocolId: Int? = null,
        val dataCodingScheme: Int? = null,
        val details: List<String> = emptyList()
    )

    suspend fun sendSms(message: Message): Result<String> = withContext(Dispatchers.IO) {
        val diagnostics = mutableListOf<String>()
        val messageId = message.id
        MessageTracker.trackMessage(
            messageId = messageId,
            destination = message.destination,
            messageType = message.type.name,
            body = message.body.orEmpty(),
            encoding = message.encoding.name,
            messageClass = message.messageClass.name
        )
        try {
            diagnostics += "Preparing ${message.type} to ${message.destination}"
            val rootAvailable = RootAccessManager.isRootAvailable()
            diagnostics += "Root available: $rootAvailable"

            var atReady = atCommandsAvailable && AtCommandManager.isInitialized()
            if (rootAvailable && !atReady) {
                diagnostics += "AT interface not initialized, attempting initialization"
                atReady = initializeAtCommandsInternal(diagnostics)
            }
            diagnostics += "AT ready: $atReady"

            val execution = when (message.type) {
                MessageType.SMS_TEXT -> sendTextSms(message, messageId, rootAvailable, atReady, diagnostics)
                MessageType.SMS_BINARY -> sendBinarySms(message, messageId, rootAvailable, atReady, diagnostics)
                MessageType.SMS_FLASH -> sendFlashSms(message, messageId, rootAvailable, atReady, diagnostics)
                MessageType.SMS_SILENT -> sendSilentSms(message, messageId, rootAvailable, atReady, diagnostics)
                else -> SendExecution(
                    result = Result.failure(Exception("Unsupported SMS type: ${message.type}")),
                    route = SmsRoute.UNSUPPORTED,
                    usedRoot = false,
                    usedAt = false,
                    details = diagnostics.toList()
                )
            }

            publishSendReport(message, execution, diagnostics + execution.details)
            execution.result
        } catch (e: Exception) {
            val failed = SendExecution(
                result = Result.failure(e),
                route = SmsRoute.EXCEPTION,
                usedRoot = false,
                usedAt = false,
                details = diagnostics + "Unhandled exception: ${e.message}"
            )
            publishSendReport(message, failed, failed.details)
            Result.failure(e)
        }
    }

    private suspend fun sendTextSms(
        message: Message,
        messageId: String,
        rootAvailable: Boolean,
        atReady: Boolean,
        diagnostics: MutableList<String>
    ): SendExecution {
        val body = message.body ?: return SendExecution(
            result = Result.failure(Exception("SMS body is required")),
            route = SmsRoute.UNSUPPORTED,
            usedRoot = false,
            usedAt = false,
            details = listOf("SMS body is required")
        )

        val info = calculateSmsInfo(body, message.encoding)
        diagnostics += "Text encoding=${info.encoding}, parts=${info.parts}, chars=${info.totalChars}"

        if (rootAvailable && atReady && info.parts == 1) {
            diagnostics += "Trying root AT text-mode send"
            val success = AtCommandManager.sendSmsText(message.destination, body)
            if (success) {
                updateStatus(messageId, DeliveryStatus.SENT)
                return SendExecution(
                    result = Result.success(messageId),
                    route = SmsRoute.ROOT_AT_TEXT,
                    usedRoot = true,
                    usedAt = true,
                    details = listOf("Sent via AT text mode on ${AtCommandManager.getInitializedDevice() ?: "unknown device"}")
                )
            }
            diagnostics += "AT text send failed, falling back"
        }

        val apiResult = sendTextSmsViaApi(message, messageId)
        return SendExecution(
            result = apiResult,
            route = if (rootAvailable && atReady) SmsRoute.ANDROID_API_FALLBACK else SmsRoute.ANDROID_API,
            usedRoot = rootAvailable,
            usedAt = false,
            details = listOf("Sent via Android SmsManager API (${info.parts} part(s))")
        )
    }

    private suspend fun sendBinarySms(
        message: Message,
        messageId: String,
        rootAvailable: Boolean,
        atReady: Boolean,
        diagnostics: MutableList<String>
    ): SendExecution {
        val payload = decodeBinaryPayload(message.body)
            ?: return SendExecution(Result.failure(Exception("Binary data required")), SmsRoute.UNSUPPORTED, false, false, details = listOf("Binary payload missing"))
        val port = message.port ?: return SendExecution(Result.failure(Exception("Destination port required for binary SMS")), SmsRoute.UNSUPPORTED, false, false, details = listOf("Destination port missing"))

        diagnostics += "Binary payload bytes=${payload.size}, port=$port"

        if (rootAvailable && atReady && payload.size <= 133) {
            val built = AtCommandManager.buildBinarySmsPdu(message.destination, payload, port)
            if (AtCommandManager.sendSmsPdu(built.pdu, built.tpduLength)) {
                updateStatus(messageId, DeliveryStatus.SENT)
                return SendExecution(
                    result = Result.success(messageId),
                    route = SmsRoute.ROOT_AT_PDU,
                    usedRoot = true,
                    usedAt = true,
                    protocolId = built.pid,
                    dataCodingScheme = built.dcs,
                    details = listOf("Binary AT PDU send complete (DCS=0x${"%02X".format(built.dcs)})")
                )
            }
        }

        val sentIntent = createPendingIntent(ACTION_SMS_SENT, messageId)
        val deliveredIntent = if (message.deliveryReport) createPendingIntent(ACTION_SMS_DELIVERED, messageId) else null
        smsManager.sendDataMessage(message.destination, null, port.toShort(), payload, sentIntent, deliveredIntent)
        updateStatus(messageId, DeliveryStatus.SENT)
        return SendExecution(
            result = Result.success(messageId),
            route = if (rootAvailable && atReady) SmsRoute.ANDROID_API_FALLBACK else SmsRoute.ANDROID_DATA_API,
            usedRoot = rootAvailable,
            usedAt = false,
            details = listOf("Sent via Android data SMS API")
        )
    }

    private suspend fun sendFlashSms(
        message: Message,
        messageId: String,
        rootAvailable: Boolean,
        atReady: Boolean,
        diagnostics: MutableList<String>
    ): SendExecution {
        if (rootAvailable && atReady) {
            val built = AtCommandManager.buildFlashSmsPdu(message.destination, message.body ?: "")
            if (AtCommandManager.sendSmsPdu(built.pdu, built.tpduLength)) {
                updateStatus(messageId, DeliveryStatus.SENT)
                return SendExecution(
                    result = Result.success(messageId),
                    route = SmsRoute.ROOT_AT_PDU,
                    usedRoot = true,
                    usedAt = true,
                    protocolId = built.pid,
                    dataCodingScheme = built.dcs,
                    details = listOf("Flash SMS sent via AT PDU (DCS=0x${"%02X".format(built.dcs)})")
                )
            }
            diagnostics += "AT flash send failed, falling back"
        }

        val fallback = sendTextSmsStandard(message.copy(messageClass = MessageClass.CLASS_0), messageId)
        return SendExecution(
            result = fallback,
            route = if (rootAvailable && atReady) SmsRoute.ANDROID_API_FALLBACK else SmsRoute.ANDROID_API,
            usedRoot = rootAvailable,
            usedAt = false,
            details = listOf("Flash fallback path used Android SmsManager text API")
        )
    }

    private suspend fun sendSilentSms(
        message: Message,
        messageId: String,
        rootAvailable: Boolean,
        atReady: Boolean,
        diagnostics: MutableList<String>
    ): SendExecution {
        if (rootAvailable && atReady) {
            val built = AtCommandManager.buildSilentSmsPdu(message.destination, message.body ?: "")
            if (AtCommandManager.sendSmsPdu(built.pdu, built.tpduLength)) {
                updateStatus(messageId, DeliveryStatus.SENT)
                return SendExecution(
                    result = Result.success(messageId),
                    route = SmsRoute.ROOT_AT_PDU,
                    usedRoot = true,
                    usedAt = true,
                    protocolId = built.pid,
                    dataCodingScheme = built.dcs,
                    details = listOf("Silent SMS sent via AT PDU (PID=0x${"%02X".format(built.pid)}, DCS=0x${"%02X".format(built.dcs)})")
                )
            }
            diagnostics += "AT silent send failed, falling back"
        }

        val fallback = sendTextSmsStandard(message, messageId)
        return SendExecution(
            result = fallback,
            route = if (rootAvailable && atReady) SmsRoute.ANDROID_API_FALLBACK else SmsRoute.ANDROID_API,
            usedRoot = rootAvailable,
            usedAt = false,
            details = listOf("Silent fallback path used Android SmsManager text API")
        )
    }

    private fun sendTextSmsViaApi(message: Message, messageId: String): Result<String> {
        val body = message.body ?: return Result.failure(Exception("SMS body is required"))
        val sentIntent = createPendingIntent(ACTION_SMS_SENT, messageId)
        val deliveredIntent = if (message.deliveryReport) createPendingIntent(ACTION_SMS_DELIVERED, messageId) else null
        val parts = smsManager.divideMessage(body)

        return if (parts.size > 1) {
            val sentIntents = ArrayList<PendingIntent>()
            val deliveredIntents = ArrayList<PendingIntent>()
            repeat(parts.size) {
                sentIntents.add(sentIntent)
                deliveredIntent?.let { deliveredIntents.add(it) }
            }
            smsManager.sendMultipartTextMessage(
                message.destination, null, parts, sentIntents, deliveredIntent?.let { deliveredIntents }
            )
            updateStatus(messageId, DeliveryStatus.SENT)
            Result.success(messageId)
        } else {
            smsManager.sendTextMessage(message.destination, null, body, sentIntent, deliveredIntent)
            updateStatus(messageId, DeliveryStatus.SENT)
            Result.success(messageId)
        }
    }

    private fun sendTextSmsStandard(message: Message, messageId: String): Result<String> {
        val body = message.body ?: ""
        val sentIntent = createPendingIntent(ACTION_SMS_SENT, messageId)
        smsManager.sendTextMessage(message.destination, null, body, sentIntent, null)
        updateStatus(messageId, DeliveryStatus.SENT)
        return Result.success(messageId)
    }

    fun calculateSmsInfo(text: String, encoding: SmsEncoding = SmsEncoding.AUTO): SmsInfo {
        val isUnicode = containsUnicodeCharacters(text)
        val actualEncoding = if (encoding == SmsEncoding.AUTO) {
            if (isUnicode) SmsEncoding.UCS2 else SmsEncoding.GSM_7BIT
        } else encoding

        val maxLength = when (actualEncoding) {
            SmsEncoding.GSM_7BIT -> SMS_MAX_LENGTH_GSM
            SmsEncoding.UCS2 -> SMS_MAX_LENGTH_UNICODE
            else -> SMS_MAX_LENGTH_GSM
        }
        val maxConcatLength = when (actualEncoding) {
            SmsEncoding.GSM_7BIT -> SMS_CONCAT_MAX_LENGTH_GSM
            SmsEncoding.UCS2 -> SMS_CONCAT_MAX_LENGTH_UNICODE
            else -> SMS_CONCAT_MAX_LENGTH_GSM
        }
        val parts = if (text.length <= maxLength) 1 else (text.length + maxConcatLength - 1) / maxConcatLength
        return SmsInfo(parts, if (parts == 1) maxLength - text.length else maxConcatLength - (text.length % maxConcatLength), actualEncoding, text.length)
    }

    private fun containsUnicodeCharacters(text: String): Boolean {
        val gsmCharset = "@£\$¥èéùìòÇ\\nØø\\rÅåΔ_ΦΓΛΩΠΨΣΘΞÆæßÉ !\\\"#¤%&'()*+,-./0123456789:;<=>?¡ABCDEFGHIJKLMNOPQRSTUVWXYZÄÖÑÜ§¿abcdefghijklmnopqrstuvwxyzäöñüà"
        val gsmExtCharset = "^{}\\\\\\[~\\]|€"
        return text.any { it !in gsmCharset && it !in gsmExtCharset }
    }

    private fun createPendingIntent(action: String, messageId: String): PendingIntent {
        val intent = Intent(action).apply { putExtra("message_id", messageId) }
        return PendingIntent.getBroadcast(
            context,
            messageId.hashCode(),
            intent,
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )
    }

    private fun updateStatus(messageId: String, status: DeliveryStatus) {
        val current = _messageStatus.value.toMutableMap()
        current[messageId] = status
        _messageStatus.value = current
    }

    fun getDefaultSmsSubscriptionId(): Int = SmsManager.getDefaultSmsSubscriptionId()

    fun getActiveSubscriptions(): List<Int> {
        if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.LOLLIPOP_MR1) {
            val subscriptionManager = context.getSystemService(SubscriptionManager::class.java)
            return subscriptionManager?.activeSubscriptionInfoList?.map { it.subscriptionId } ?: emptyList()
        }
        return emptyList()
    }

    suspend fun initializeAtCommands(): Boolean {
        val diagnostics = mutableListOf<String>()
        return initializeAtCommandsInternal(diagnostics)
    }

    private suspend fun initializeAtCommandsInternal(diagnostics: MutableList<String>): Boolean {
        return try {
            Logger.d(TAG, "Initializing AT command interface...")
            diagnostics += "Initializing AT command interface"

            if (!RootAccessManager.isRootAvailable()) {
                Log.i(TAG, "Root not available, AT commands disabled")
                diagnostics += "Root unavailable, cannot initialize AT"
                atCommandsAvailable = false
                return false
            }

            val devices = AtCommandManager.probeDevices()
            if (devices.isEmpty()) {
                diagnostics += "No modem devices responded to AT probing"
                atCommandsAvailable = false
                return false
            }

            diagnostics += "Candidate AT devices: ${devices.joinToString()}"
            for (device in devices) {
                if (AtCommandManager.initializeAtOnDevice(device)) {
                    atCommandsAvailable = true
                    diagnostics += "AT initialized on $device"
                    return true
                }
                diagnostics += "AT init failed on $device"
            }
            atCommandsAvailable = false
            false
        } catch (e: Exception) {
            diagnostics += "AT initialization exception: ${e.message}"
            atCommandsAvailable = false
            false
        }
    }

    fun areAtCommandsAvailable(): Boolean = atCommandsAvailable
    suspend fun checkRootAccess(): Boolean = RootAccessManager.isRootAvailable()
    fun getModemDevice(): String? = AtCommandManager.getInitializedDevice()

    private fun decodeBinaryPayload(body: String?): ByteArray? {
        val value = body?.trim() ?: return null
        if (value.isEmpty()) return ByteArray(0)
        val collapsed = value.replace("\\s+".toRegex(), "")
        val looksHex = collapsed.matches(Regex("^[0-9A-Fa-f]+$")) && collapsed.length % 2 == 0
        return if (looksHex) collapsed.chunked(2).map { it.toInt(16).toByte() }.toByteArray() else value.toByteArray(Charsets.UTF_8)
    }

    private fun publishSendReport(message: Message, execution: SendExecution, details: List<String>) {
        val parts = when (message.type) {
            MessageType.SMS_TEXT, MessageType.SMS_FLASH, MessageType.SMS_SILENT -> calculateSmsInfo(message.body.orEmpty(), message.encoding).parts
            else -> 1
        }
        val report = SmsSendReport(
            messageId = message.id,
            destination = message.destination,
            type = message.type,
            success = execution.result.isSuccess,
            route = execution.route,
            usedRoot = execution.usedRoot,
            usedAt = execution.usedAt,
            modemDevice = AtCommandManager.getInitializedDevice(),
            encoding = message.encoding,
            parts = parts,
            protocolId = execution.protocolId,
            dataCodingScheme = execution.dataCodingScheme,
            details = details.takeLast(20),
            error = execution.result.exceptionOrNull()?.message
        )
        _lastSendReport.value = report

        val statusLabel = if (report.success) "success" else "failed"
        RootAccessManager.logActivity(
            "SMS ${message.type} $statusLabel via ${report.route}",
            if (report.success) RootActivityType.SUCCESS else RootActivityType.ERROR
        )
        if (!report.success) updateStatus(message.id, DeliveryStatus.FAILED)
        MessageTracker.updateStatus(
            messageId = message.id,
            status = if (report.success) MessageTracker.STATUS_SENT else MessageTracker.STATUS_FAILED,
            details = report.error ?: report.details.lastOrNull() ?: ""
        )
    }
}

data class SmsInfo(
    val parts: Int,
    val remainingChars: Int,
    val encoding: SmsEncoding,
    val totalChars: Int
)

enum class SmsRoute {
    ROOT_AT_PDU,
    ROOT_AT_TEXT,
    ANDROID_API,
    ANDROID_DATA_API,
    ANDROID_API_FALLBACK,
    UNSUPPORTED,
    EXCEPTION
}

data class SmsSendReport(
    val messageId: String,
    val destination: String,
    val type: MessageType,
    val success: Boolean,
    val route: SmsRoute,
    val usedRoot: Boolean,
    val usedAt: Boolean,
    val modemDevice: String?,
    val encoding: SmsEncoding,
    val parts: Int,
    val protocolId: Int?,
    val dataCodingScheme: Int?,
    val details: List<String>,
    val error: String? = null,
    val timestamp: Long = System.currentTimeMillis()
)
