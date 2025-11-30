package com.zerosms.testing.core.sms

import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.telephony.SmsManager
import android.telephony.SubscriptionManager
import android.util.Log
import com.zerosms.testing.core.Logger
import com.zerosms.testing.core.at.AtCommandManager
import com.zerosms.testing.core.root.RootAccessManager
import com.zerosms.testing.core.model.*
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.withContext
import java.util.Date
import java.util.UUID

/**
 * SMS Manager implementing RFC-compliant SMS operations
 * Supports GSM 03.40, GSM 03.38, 3GPP TS 23.040
 * 
 * ENHANCED: Supports AT command sending for Class 0/Type 0 SMS
 */
class SmsManagerWrapper(private val context: Context) {
    
    private val TAG = "SmsManagerWrapper"
    
    // AT command support (requires root) - now uses singleton objects
    private var atCommandsAvailable = false
    
    private val smsManager: SmsManager = context.getSystemService(SmsManager::class.java)
    private val _messageStatus = MutableStateFlow<Map<String, DeliveryStatus>>(emptyMap())
    val messageStatus: Flow<Map<String, DeliveryStatus>> = _messageStatus.asStateFlow()
    
    companion object {
        const val SMS_MAX_LENGTH_GSM = 160
        const val SMS_MAX_LENGTH_UNICODE = 70
        const val SMS_CONCAT_MAX_LENGTH_GSM = 153  // 160 - 7 bytes UDH
        const val SMS_CONCAT_MAX_LENGTH_UNICODE = 67  // 70 - 3 bytes UDH
        
        const val ACTION_SMS_SENT = "com.zerosms.testing.SMS_SENT"
        const val ACTION_SMS_DELIVERED = "com.zerosms.testing.SMS_DELIVERED"
    }
    
    /**
     * Send SMS with full RFC compliance options
     */
    suspend fun sendSms(message: Message): Result<String> = withContext(Dispatchers.IO) {
        try {
            val messageId = message.id
            
            when (message.type) {
                MessageType.SMS_TEXT -> sendTextSms(message, messageId)
                MessageType.SMS_BINARY -> sendBinarySms(message, messageId)
                MessageType.SMS_FLASH -> sendFlashSms(message, messageId)
                MessageType.SMS_SILENT -> sendSilentSms(message, messageId)
                else -> Result.failure(Exception("Unsupported SMS type: ${message.type}"))
            }
        } catch (e: Exception) {
            Result.failure(e)
        }
    }
    
    /**
     * Send standard text SMS (GSM 03.40)
     */
    private fun sendTextSms(message: Message, messageId: String): Result<String> {
        val body = message.body ?: return Result.failure(Exception("SMS body is required"))
        
        val sentIntent = createPendingIntent(ACTION_SMS_SENT, messageId)
        val deliveredIntent = if (message.deliveryReport) {
            createPendingIntent(ACTION_SMS_DELIVERED, messageId)
        } else null
        
        // Check if message needs to be split
        val parts = smsManager.divideMessage(body)
        
        return if (parts.size > 1) {
            // Send multipart SMS (concatenated)
            val sentIntents = ArrayList<PendingIntent>()
            val deliveredIntents = ArrayList<PendingIntent>()
            
            repeat(parts.size) {
                sentIntents.add(sentIntent)
                deliveredIntent?.let { deliveredIntents.add(it) }
            }
            
            smsManager.sendMultipartTextMessage(
                message.destination,
                null,
                parts,
                sentIntents,
                if (deliveredIntent != null) deliveredIntents else null
            )
            
            updateStatus(messageId, DeliveryStatus.SENT)
            Result.success(messageId)
        } else {
            // Send single SMS
            smsManager.sendTextMessage(
                message.destination,
                null,
                body,
                sentIntent,
                deliveredIntent
            )
            
            updateStatus(messageId, DeliveryStatus.SENT)
            Result.success(messageId)
        }
    }
    
    /**
     * Send binary SMS (GSM 03.40 - 8-bit data)
     */
    private fun sendBinarySms(message: Message, messageId: String): Result<String> {
        val data = message.body?.toByteArray() ?: return Result.failure(Exception("Binary data required"))
        val port = message.port ?: return Result.failure(Exception("Destination port required for binary SMS"))
        
        val sentIntent = createPendingIntent(ACTION_SMS_SENT, messageId)
        val deliveredIntent = if (message.deliveryReport) {
            createPendingIntent(ACTION_SMS_DELIVERED, messageId)
        } else null
        
        smsManager.sendDataMessage(
            message.destination,
            null,
            port.toShort(),
            data,
            sentIntent,
            deliveredIntent
        )
        
        updateStatus(messageId, DeliveryStatus.SENT)
        return Result.success(messageId)
    }
    
    /**
     * Send Flash SMS (Class 0) - Immediate display without saving
     * Tries AT commands first, falls back to standard API
     */
    private suspend fun sendFlashSms(message: Message, messageId: String): Result<String> {
        // Try AT commands first for proper Class 0 SMS
        if (atCommandsAvailable && AtCommandManager.isInitialized()) {
            Logger.d(TAG, "Sending Flash SMS via AT commands for proper Class 0")
            val (pdu, tpduLen) = AtCommandManager.buildFlashSmsPdu(
                message.destination,
                message.body ?: ""
            )
            val success = AtCommandManager.sendSmsPdu(pdu, tpduLen)
            return if (success) {
                updateStatus(messageId, DeliveryStatus.SENT)
                Result.success(messageId)
            } else {
                Logger.w(TAG, "AT command failed, falling back to standard API")
                sendTextSms(message.copy(messageClass = MessageClass.CLASS_0), messageId)
            }
        }
        
        // Fallback: Standard API (Class 0 support varies by device)
        Logger.w(TAG, "AT commands unavailable, using standard API for Flash SMS")
        return sendTextSms(
            message.copy(messageClass = MessageClass.CLASS_0),
            messageId
        )
    }
    
    /**
     * Send Silent SMS (Type 0) - No user notification
     * Used for network testing and location tracking
     */
    private suspend fun sendSilentSms(message: Message, messageId: String): Result<String> {
        // Try AT commands first for proper Type 0 SMS
        if (atCommandsAvailable && AtCommandManager.isInitialized()) {
            Logger.d(TAG, "Sending Silent SMS via AT commands for proper Type 0")
            val success = AtCommandManager.sendSmsText(
                message.destination,
                message.body ?: ""
            )
            return if (success) {
                updateStatus(messageId, DeliveryStatus.SENT)
                Result.success(messageId)
            } else {
                Logger.w(TAG, "AT command failed, falling back to standard API")
                sendTextSmsStandard(message, messageId)
            }
        }
        
        // Fallback: Standard API (Type 0 support varies by device)
        Logger.w(TAG, "AT commands unavailable, using standard API for Silent SMS")
        return sendTextSmsStandard(message, messageId)
    }
    
    /**
     * Simple text SMS via standard API (fallback)
     */
    private fun sendTextSmsStandard(message: Message, messageId: String): Result<String> {
        val body = message.body ?: ""
        val sentIntent = createPendingIntent(ACTION_SMS_SENT, messageId)
        
        smsManager.sendTextMessage(
            message.destination,
            null,
            body,
            sentIntent,
            null
        )
        
        updateStatus(messageId, DeliveryStatus.SENT)
        return Result.success(messageId)
    }
    
    /**
     * Calculate SMS parts and length (GSM 03.38 compliant)
     */
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
        
        val parts = if (text.length <= maxLength) {
            1
        } else {
            (text.length + maxConcatLength - 1) / maxConcatLength
        }
        
        return SmsInfo(
            parts = parts,
            remainingChars = if (parts == 1) maxLength - text.length else maxConcatLength - (text.length % maxConcatLength),
            encoding = actualEncoding,
            totalChars = text.length
        )
    }
    
    /**
     * Check for Unicode characters requiring UCS-2 encoding
     */
    private fun containsUnicodeCharacters(text: String): Boolean {
        val gsmCharset = "@£\$¥èéùìòÇ\\nØø\\rÅåΔ_ΦΓΛΩΠΨΣΘΞÆæßÉ !\\\"#¤%&'()*+,-./0123456789:;<=>?¡ABCDEFGHIJKLMNOPQRSTUVWXYZÄÖÑÜ§¿abcdefghijklmnopqrstuvwxyzäöñüà"
        val gsmExtCharset = "^{}\\\\\\[~\\]|€"
        
        return text.any { char ->
            char !in gsmCharset && char !in gsmExtCharset
        }
    }
    
    private fun createPendingIntent(action: String, messageId: String): PendingIntent {
        val intent = Intent(action).apply {
            putExtra("message_id", messageId)
        }
        return PendingIntent.getBroadcast(
            context,
            messageId.hashCode(),
            intent,
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )
    }
    
    private fun updateStatus(messageId: String, status: DeliveryStatus) {
        val currentMap = _messageStatus.value.toMutableMap()
        currentMap[messageId] = status
        _messageStatus.value = currentMap
    }
    
    /**
     * Get default SMS subscription ID for dual-SIM devices
     */
    fun getDefaultSmsSubscriptionId(): Int {
        return SmsManager.getDefaultSmsSubscriptionId()
    }
    
    /**
     * Get all active SIM subscriptions
     */
    fun getActiveSubscriptions(): List<Int> {
        if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.LOLLIPOP_MR1) {
            val subscriptionManager = context.getSystemService(SubscriptionManager::class.java)
            return subscriptionManager?.activeSubscriptionInfoList?.map { it.subscriptionId } ?: emptyList()
        }
        return emptyList()
    }
    
    /**
     * Initialize AT command interface (requires root)
     * Call this once during app startup
     */
    suspend fun initializeAtCommands(): Boolean {
        return try {
            Logger.d(TAG, "Initializing AT command interface...")
            
            // Check root first
            if (!RootAccessManager.isRootAvailable()) {
                Log.i(TAG, "Root not available, AT commands disabled")
                atCommandsAvailable = false
                return false
            }
            
            // Probe for devices
            val devices = AtCommandManager.probeDevices()
            if (devices.isEmpty()) {
                Log.i(TAG, "No modem devices found")
                atCommandsAvailable = false
                return false
            }
            
            // Try to initialize on first available device
            for (device in devices) {
                if (AtCommandManager.initializeAtOnDevice(device)) {
                    atCommandsAvailable = true
                    Log.i(TAG, "AT commands initialized on $device")
                    return true
                }
            }
            
            atCommandsAvailable = false
            false
        } catch (e: Exception) {
            Log.e(TAG, "Failed to initialize AT commands", e)
            atCommandsAvailable = false
            false
        }
    }
    
    /**
     * Check if AT commands are available
     */
    fun areAtCommandsAvailable(): Boolean = atCommandsAvailable
    
    /**
     * Check if device has root access
     */
    suspend fun checkRootAccess(): Boolean {
        return RootAccessManager.isRootAvailable()
    }
    
    /**
     * Get modem device path (if AT commands are available)
     */
    fun getModemDevice(): String? = AtCommandManager.getInitializedDevice()
}

/**
 * SMS information for length calculation
 */
data class SmsInfo(
    val parts: Int,
    val remainingChars: Int,
    val encoding: SmsEncoding,
    val totalChars: Int
)
