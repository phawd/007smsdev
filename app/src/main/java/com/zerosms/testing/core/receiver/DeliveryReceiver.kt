package com.zerosms.testing.core.receiver

import android.app.Activity
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.telephony.SmsManager
import android.util.Log
import com.zerosms.testing.core.model.DeliveryStatus

/**
 * Delivery Report Receiver for SMS delivery status
 * Handles SMS_SENT and SMS_DELIVERED intents
 */
class DeliveryReceiver : BroadcastReceiver() {
    
    companion object {
        private const val TAG = "DeliveryReceiver"
        const val ACTION_SMS_SENT = "com.zerosms.testing.SMS_SENT"
        const val ACTION_SMS_DELIVERED = "com.zerosms.testing.SMS_DELIVERED"
    }
    
    override fun onReceive(context: Context, intent: Intent) {
        val messageId = intent.getStringExtra("message_id") ?: return
        
        when (intent.action) {
            ACTION_SMS_SENT -> handleSmsSent(messageId, resultCode)
            ACTION_SMS_DELIVERED -> handleSmsDelivered(messageId, resultCode)
        }
    }
    
    /**
     * Handle SMS sent status
     */
    private fun handleSmsSent(messageId: String, resultCode: Int) {
        when (resultCode) {
            Activity.RESULT_OK -> {
                Log.i(TAG, "SMS sent successfully: $messageId")
                updateDeliveryStatus(messageId, DeliveryStatus.SENT)
            }
            SmsManager.RESULT_ERROR_GENERIC_FAILURE -> {
                Log.e(TAG, "SMS generic failure: $messageId")
                updateDeliveryStatus(messageId, DeliveryStatus.FAILED)
            }
            SmsManager.RESULT_ERROR_NO_SERVICE -> {
                Log.e(TAG, "SMS no service: $messageId")
                updateDeliveryStatus(messageId, DeliveryStatus.FAILED)
            }
            SmsManager.RESULT_ERROR_NULL_PDU -> {
                Log.e(TAG, "SMS null PDU: $messageId")
                updateDeliveryStatus(messageId, DeliveryStatus.FAILED)
            }
            SmsManager.RESULT_ERROR_RADIO_OFF -> {
                Log.e(TAG, "SMS radio off: $messageId")
                updateDeliveryStatus(messageId, DeliveryStatus.FAILED)
            }
            else -> {
                Log.w(TAG, "SMS unknown result: $messageId, code: $resultCode")
                updateDeliveryStatus(messageId, DeliveryStatus.FAILED)
            }
        }
    }
    
    /**
     * Handle SMS delivered status
     */
    private fun handleSmsDelivered(messageId: String, resultCode: Int) {
        when (resultCode) {
            Activity.RESULT_OK -> {
                Log.i(TAG, "SMS delivered successfully: $messageId")
                updateDeliveryStatus(messageId, DeliveryStatus.DELIVERED)
            }
            Activity.RESULT_CANCELED -> {
                Log.e(TAG, "SMS delivery cancelled: $messageId")
                updateDeliveryStatus(messageId, DeliveryStatus.UNDELIVERABLE)
            }
            else -> {
                Log.w(TAG, "SMS delivery unknown result: $messageId, code: $resultCode")
                updateDeliveryStatus(messageId, DeliveryStatus.FAILED)
            }
        }
    }
    
    /**
     * Update delivery status
     * In a real app, this would update a database or notify observers
     */
    private fun updateDeliveryStatus(messageId: String, status: DeliveryStatus) {
        // Notify app components about status change
        // This could be done via:
        // 1. LocalBroadcastManager
        // 2. EventBus
        // 3. LiveData/StateFlow
        // 4. Database update
        
        Log.d(TAG, "Status updated: $messageId -> $status")
    }
}
