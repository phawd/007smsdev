package com.smstest.app.core.receiver

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.os.Bundle
import android.telephony.SmsMessage
import android.util.Log
import com.smstest.app.core.database.IncomingSms
import com.smstest.app.core.database.IncomingSmsDatabase
import com.smstest.app.core.model.DeliveryStatus
import com.smstest.app.core.model.Message
import com.smstest.app.core.model.MessageClass
import com.smstest.app.core.model.MessageType
import com.smstest.app.core.model.SmsEncoding
import java.util.Date
import java.util.UUID

/**
 * SMS Broadcast Receiver for incoming SMS messages
 * Handles SMS_RECEIVED and SMS_DELIVER intents per Android Telephony API
 * 
 * ENHANCED: Captures and stores Class 0 (Flash) and Type 0 (Silent) SMS
 * for operator monitoring.
 */
class SmsReceiver : BroadcastReceiver() {
    
    companion object {
        private const val TAG = "SmsReceiver"
        const val SMS_RECEIVED_ACTION = "android.provider.Telephony.SMS_RECEIVED"
        const val SMS_DELIVER_ACTION = "android.provider.Telephony.SMS_DELIVER"
        
        // Shared database instance (in production, use dependency injection)
        @Volatile
        private var database: IncomingSmsDatabase? = null
        
        fun getDatabase(): IncomingSmsDatabase {
            return database ?: synchronized(this) {
                database ?: IncomingSmsDatabase().also { database = it }
            }
        }
    }
    
    override fun onReceive(context: Context, intent: Intent) {
        when (intent.action) {
            SMS_RECEIVED_ACTION, SMS_DELIVER_ACTION -> {
                handleIncomingSms(context, intent)
            }
        }
    }
    
    /**
     * Handle incoming SMS message
     */
    private fun handleIncomingSms(context: Context, intent: Intent) {
        try {
            val bundle: Bundle? = intent.extras
            if (bundle != null) {
                val pdus = bundle.get("pdus") as Array<*>?
                val format = bundle.getString("format")
                
                pdus?.forEach { pdu ->
                    val smsMessage = if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.M) {
                        SmsMessage.createFromPdu(pdu as ByteArray, format)
                    } else {
                        @Suppress("DEPRECATION")
                        SmsMessage.createFromPdu(pdu as ByteArray)
                    }
                    
                    smsMessage?.let { message ->
                        processSmsMessage(context, message)
                    }
                }
            }
        } catch (e: Exception) {
            Log.e(TAG, "Error receiving SMS", e)
        }
    }
    
    /**
     * Process received SMS message
     * ENHANCED: Detects and stores Class 0 (Flash) and Type 0 (Silent) SMS
     */
    private fun processSmsMessage(context: Context, smsMessage: SmsMessage) {
        val sender = smsMessage.originatingAddress ?: "Unknown"
        val body = smsMessage.messageBody ?: ""
        val timestamp = smsMessage.timestampMillis
        val androidMessageClass = smsMessage.messageClass
        val protocolId = smsMessage.protocolIdentifier
        
        // Detect message class
        val messageClass = when (androidMessageClass) {
            SmsMessage.MessageClass.CLASS_0 -> MessageClass.CLASS_0
            SmsMessage.MessageClass.CLASS_1 -> MessageClass.CLASS_1
            SmsMessage.MessageClass.CLASS_2 -> MessageClass.CLASS_2
            SmsMessage.MessageClass.CLASS_3 -> MessageClass.CLASS_3
            else -> MessageClass.NONE
        }
        
        // Detect Type 0 (Silent SMS) - PID = 0x40
        val isSilent = protocolId == 0x40
        val isFlash = messageClass == MessageClass.CLASS_0
        
        // Determine message type
        val messageType = when {
            isSilent -> MessageType.SMS_SILENT
            isFlash -> MessageType.SMS_FLASH
            else -> MessageType.SMS_TEXT
        }
        
        // Detect encoding
        val encoding = detectEncoding(body)
        
        // Get PDU if available
        val rawPdu = try {
            smsMessage.pdu?.joinToString("") { "%02X".format(it) }
        } catch (e: Exception) {
            null
        }
        
        Log.d(TAG, """
            Received SMS from $sender:
            Class: $messageClass
            Type: $messageType
            PID: 0x${protocolId.toString(16)}
            Silent: $isSilent
            Flash: $isFlash
            Body: $body
        """.trimIndent())
        
        // Create database entry
        val incomingSms = IncomingSms(
            id = UUID.randomUUID().toString(),
            sender = sender,
            body = body,
            timestamp = timestamp,
            messageClass = messageClass,
            messageType = messageType,
            encoding = encoding,
            protocolId = protocolId,
            isFlash = isFlash,
            isSilent = isSilent,
            isRead = false,
            rawPdu = rawPdu
        )
        
        // Store in database
        getDatabase().addMessage(incomingSms)
        
        // Log for operator monitoring
        logReceivedMessage(incomingSms)
        
        // For Flash SMS (Class 0), prevent system from dismissing
        // by consuming the broadcast (optional - depends on requirements)
        if (isFlash || isSilent) {
            Log.i(TAG, "Captured ${if (isFlash) "Flash" else "Silent"} SMS for operator monitoring")
        }
    }
    
    /**
     * Detect SMS encoding from body
     */
    private fun detectEncoding(body: String): SmsEncoding {
        return when {
            body.isEmpty() -> SmsEncoding.GSM_7BIT
            body.any { it.code > 127 } -> SmsEncoding.UCS2
            else -> SmsEncoding.GSM_7BIT
        }
    }
    
    /**
     * Log received message for operator monitoring
     */
    private fun logReceivedMessage(message: IncomingSms) {
        val typeLabel = when {
            message.isSilent -> "SILENT (Type 0)"
            message.isFlash -> "FLASH (Class 0)"
            else -> "NORMAL"
        }
        
        Log.i(TAG, """
            |==================== SMS RECEIVED ====================
            |Type:     $typeLabel
            |From:     ${message.sender}
            |Time:     ${Date(message.timestamp)}
            |Class:    ${message.messageClass}
            |PID:      0x${message.protocolId.toString(16)}
            |Encoding: ${message.encoding}
            |Body:     ${message.body}
            |PDU:      ${message.rawPdu ?: "N/A"}
            |======================================================
        """.trimMargin())
    }
}
