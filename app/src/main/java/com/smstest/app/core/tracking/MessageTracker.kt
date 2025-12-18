package com.smstest.app.core.tracking

import android.util.Log
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import java.text.SimpleDateFormat
import java.util.*
import java.util.concurrent.ConcurrentHashMap

/**
 * Message Tracker for comprehensive SMS/MMS/RCS tracking
 * Provides verbose logging, status tracking, and event notifications
 */
object MessageTracker {
    private const val TAG = "MessageTracker"
    
    // Track all messages with their current status
    private val _messages = MutableStateFlow<Map<String, TrackedMessage>>(emptyMap())
    val messages: StateFlow<Map<String, TrackedMessage>> = _messages.asStateFlow()
    
    // Event log for verbose display
    private val _eventLog = MutableStateFlow<List<LogEvent>>(emptyList())
    val eventLog: StateFlow<List<LogEvent>> = _eventLog.asStateFlow()
    
    // Notification events for popups/snackbars
    private val _notifications = MutableStateFlow<List<NotificationEvent>>(emptyList())
    val notifications: StateFlow<List<NotificationEvent>> = _notifications.asStateFlow()
    
    private val messageMap = ConcurrentHashMap<String, TrackedMessage>()
    private val eventList = mutableListOf<LogEvent>()
    private val notificationList = mutableListOf<NotificationEvent>()
    
    private val dateFormat = SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS", Locale.getDefault())
    
    /**
     * Track a new message being sent
     */
    fun trackMessage(
        messageId: String,
        destination: String,
        messageType: String,
        body: String,
        encoding: String,
        messageClass: String
    ) {
        val message = TrackedMessage(
            id = messageId,
            destination = destination,
            type = messageType,
            body = body,
            encoding = encoding,
            messageClass = messageClass,
            status = "PREPARING",
            createdAt = System.currentTimeMillis()
        )
        
        messageMap[messageId] = message
        _messages.value = messageMap.toMap()
        
        logEvent("INFO", "Message $messageId created for $destination")
        addNotification("📤 Preparing message", "To: $destination", NotificationLevel.INFO)
        
        Log.i(TAG, "Tracking new message: $messageId to $destination")
    }
    
    /**
     * Update message status with detailed logging
     */
    fun updateStatus(messageId: String, status: String, details: String = "") {
        messageMap[messageId]?.let { msg ->
            val updated = msg.copy(
                status = status,
                lastUpdate = System.currentTimeMillis(),
                statusHistory = msg.statusHistory + StatusUpdate(status, details, System.currentTimeMillis())
            )
            messageMap[messageId] = updated
            _messages.value = messageMap.toMap()
            
            val detailsStr = if (details.isNotEmpty()) "- $details" else ""
            logEvent("STATUS", "$messageId: $status $detailsStr")
            
            // Create notification based on status
            when (status) {
                "SENT" -> addNotification("✅ Message Sent", "ID: ${messageId.take(8)}", NotificationLevel.SUCCESS)
                "DELIVERED" -> addNotification("🎉 Message Delivered", "ID: ${messageId.take(8)}", NotificationLevel.SUCCESS)
                "FAILED" -> addNotification("❌ Send Failed", details.ifEmpty { "Unknown error" }, NotificationLevel.ERROR)
                "PENDING" -> addNotification("⏳ Sending...", "ID: ${messageId.take(8)}", NotificationLevel.INFO)
            }
            
            Log.i(TAG, "Status update: $messageId -> $status: $details")
        } ?: Log.w(TAG, "Message not found: $messageId")
    }
    
    /**
     * Log an event with timestamp
     */
    fun logEvent(level: String, message: String) {
        val event = LogEvent(
            timestamp = System.currentTimeMillis(),
            level = level,
            message = message,
            threadName = Thread.currentThread().name
        )
        
        synchronized(eventList) {
            eventList.add(0, event) // Add to beginning
            if (eventList.size > 500) {
                eventList.removeAt(eventList.lastIndex) // Keep last 500
            }
            _eventLog.value = eventList.toList()
        }
        
        when (level) {
            "ERROR" -> Log.e(TAG, message)
            "WARN" -> Log.w(TAG, message)
            "INFO" -> Log.i(TAG, message)
            "DEBUG" -> Log.d(TAG, message)
            else -> Log.v(TAG, message)
        }
    }
    
    /**
     * Add notification for popup/snackbar
     */
    private fun addNotification(title: String, message: String, level: NotificationLevel) {
        val notification = NotificationEvent(
            id = UUID.randomUUID().toString(),
            timestamp = System.currentTimeMillis(),
            title = title,
            message = message,
            level = level,
            dismissed = false
        )
        
        synchronized(notificationList) {
            notificationList.add(0, notification)
            if (notificationList.size > 50) {
                notificationList.removeAt(notificationList.lastIndex)
            }
            _notifications.value = notificationList.toList()
        }
    }
    
    /**
     * Dismiss a notification
     */
    fun dismissNotification(notificationId: String) {
        synchronized(notificationList) {
            val index = notificationList.indexOfFirst { it.id == notificationId }
            if (index >= 0) {
                notificationList[index] = notificationList[index].copy(dismissed = true)
                _notifications.value = notificationList.toList()
            }
        }
    }
    
    /**
     * Clear old logs and notifications
     */
    fun clearOldData(olderThanMillis: Long = 3600000) { // Default 1 hour
        val cutoff = System.currentTimeMillis() - olderThanMillis
        
        synchronized(eventList) {
            eventList.removeAll { it.timestamp < cutoff }
            _eventLog.value = eventList.toList()
        }
        
        synchronized(notificationList) {
            notificationList.removeAll { it.timestamp < cutoff || it.dismissed }
            _notifications.value = notificationList.toList()
        }
    }
    
    /**
     * Get message by ID
     */
    fun getMessage(messageId: String): TrackedMessage? = messageMap[messageId]
    
    /**
     * Get all messages
     */
    fun getAllMessages(): List<TrackedMessage> = messageMap.values.toList()
    
    /**
     * Clear all tracking data
     */
    fun clearAll() {
        messageMap.clear()
        eventList.clear()
        notificationList.clear()
        _messages.value = emptyMap()
        _eventLog.value = emptyList()
        _notifications.value = emptyList()
        logEvent("INFO", "All tracking data cleared")
    }
}

/**
 * Tracked message data class
 */
data class TrackedMessage(
    val id: String,
    val destination: String,
    val type: String,
    val body: String,
    val encoding: String,
    val messageClass: String,
    val status: String,
    val createdAt: Long,
    val lastUpdate: Long = createdAt,
    val statusHistory: List<StatusUpdate> = emptyList()
)

/**
 * Status update entry
 */
data class StatusUpdate(
    val status: String,
    val details: String,
    val timestamp: Long
)

/**
 * Log event for verbose display
 */
data class LogEvent(
    val timestamp: Long,
    val level: String,
    val message: String,
    val threadName: String
)

/**
 * Notification event for popups
 */
data class NotificationEvent(
    val id: String,
    val timestamp: Long,
    val title: String,
    val message: String,
    val level: NotificationLevel,
    val dismissed: Boolean
)

enum class NotificationLevel {
    INFO, SUCCESS, WARNING, ERROR
}
