package com.smstest.app.core.receiver

import android.app.Activity
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.telephony.SmsManager
import com.smstest.app.core.Logger
import com.smstest.app.core.model.DeliveryStatus
import com.smstest.app.core.tracking.MessageTracker

/**
 * Delivery Report Receiver for SMS delivery status
 * Handles SMS_SENT and SMS_DELIVERED intents
 */
class DeliveryReceiver : BroadcastReceiver() {

    companion object {
        private const val TAG = "DeliveryReceiver"
        const val ACTION_SMS_SENT = "com.smstest.app.SMS_SENT"
        const val ACTION_SMS_DELIVERED = "com.smstest.app.SMS_DELIVERED"
    }

    override fun onReceive(context: Context, intent: Intent) {
        val messageId = intent.getStringExtra("message_id") ?: return

        when (intent.action) {
            ACTION_SMS_SENT -> handleSmsSent(messageId, resultCode)
            ACTION_SMS_DELIVERED -> handleSmsDelivered(messageId, resultCode)
        }
    }

    private fun handleSmsSent(messageId: String, resultCode: Int) {
        when (resultCode) {
            Activity.RESULT_OK -> {
                Logger.i(TAG, "SMS sent successfully: $messageId")
                updateDeliveryStatus(messageId, DeliveryStatus.SENT, "SENT")
            }
            SmsManager.RESULT_ERROR_GENERIC_FAILURE -> {
                Logger.e(TAG, "SMS generic failure: $messageId")
                updateDeliveryStatus(messageId, DeliveryStatus.FAILED, "FAILED", "Generic failure")
            }
            SmsManager.RESULT_ERROR_NO_SERVICE -> {
                Logger.e(TAG, "SMS no service: $messageId")
                updateDeliveryStatus(messageId, DeliveryStatus.FAILED, "FAILED", "No service")
            }
            SmsManager.RESULT_ERROR_NULL_PDU -> {
                Logger.e(TAG, "SMS null PDU: $messageId")
                updateDeliveryStatus(messageId, DeliveryStatus.FAILED, "FAILED", "Null PDU")
            }
            SmsManager.RESULT_ERROR_RADIO_OFF -> {
                Logger.e(TAG, "SMS radio off: $messageId")
                updateDeliveryStatus(messageId, DeliveryStatus.FAILED, "FAILED", "Radio off")
            }
            else -> {
                Logger.w(TAG, "SMS unknown result: $messageId, code: $resultCode")
                updateDeliveryStatus(messageId, DeliveryStatus.FAILED, "FAILED", "Unknown result code $resultCode")
            }
        }
    }

    private fun handleSmsDelivered(messageId: String, resultCode: Int) {
        when (resultCode) {
            Activity.RESULT_OK -> {
                Logger.i(TAG, "SMS delivered successfully: $messageId")
                updateDeliveryStatus(messageId, DeliveryStatus.DELIVERED, "DELIVERED")
            }
            Activity.RESULT_CANCELED -> {
                Logger.e(TAG, "SMS delivery cancelled: $messageId")
                updateDeliveryStatus(messageId, DeliveryStatus.UNDELIVERABLE, "FAILED", "Delivery cancelled")
            }
            else -> {
                Logger.w(TAG, "SMS delivery unknown result: $messageId, code: $resultCode")
                updateDeliveryStatus(messageId, DeliveryStatus.FAILED, "FAILED", "Unknown delivery result $resultCode")
            }
        }
    }

    private fun updateDeliveryStatus(
        messageId: String,
        status: DeliveryStatus,
        trackerStatus: String,
        details: String = ""
    ) {
        Logger.d(TAG, "Status updated: $messageId -> $status")
        MessageTracker.updateStatus(messageId, trackerStatus, details)
    }
}

