package com.smstest.app.core.database

import com.smstest.app.core.model.MessageClass
import com.smstest.app.core.model.MessageType
import com.smstest.app.core.model.SmsEncoding

/**
 * Incoming SMS entity for database storage
 * Stores all SMS including Class 0 (Flash) and Type 0 (Silent)
 */
data class IncomingSms(
    val id: String,
    val sender: String,
    val body: String,
    val timestamp: Long,
    val messageClass: MessageClass,
    val messageType: MessageType,
    val encoding: SmsEncoding,
    val protocolId: Int,  // PID - 0x40 for Type 0 (Silent)
    val isFlash: Boolean,  // Class 0
    val isSilent: Boolean,  // Type 0
    val isRead: Boolean = false,
    val rawPdu: String? = null
)

/**
 * Simple in-memory database for incoming SMS
 * Replace with Room for production
 */
class IncomingSmsDatabase {
    
    private val messages = mutableListOf<IncomingSms>()
    private val listeners = mutableListOf<(IncomingSms) -> Unit>()
    
    /**
     * Add incoming SMS to database
     */
    fun addMessage(message: IncomingSms) {
        synchronized(messages) {
            messages.add(0, message)  // Add to beginning (newest first)
            
            // Notify listeners
            listeners.forEach { it(message) }
        }
    }
    
    /**
     * Get all messages
     */
    fun getAllMessages(): List<IncomingSms> {
        synchronized(messages) {
            return messages.toList()
        }
    }
    
    /**
     * Get Flash SMS only (Class 0)
     */
    fun getFlashMessages(): List<IncomingSms> {
        synchronized(messages) {
            return messages.filter { it.isFlash }
        }
    }
    
    /**
     * Get Silent SMS only (Type 0)
     */
    fun getSilentMessages(): List<IncomingSms> {
        synchronized(messages) {
            return messages.filter { it.isSilent }
        }
    }
    
    /**
     * Get message by ID
     */
    fun getMessageById(id: String): IncomingSms? {
        synchronized(messages) {
            return messages.firstOrNull { it.id == id }
        }
    }
    
    /**
     * Mark message as read
     */
    fun markAsRead(id: String) {
        synchronized(messages) {
            val index = messages.indexOfFirst { it.id == id }
            if (index >= 0) {
                messages[index] = messages[index].copy(isRead = true)
            }
        }
    }
    
    /**
     * Delete message
     */
    fun deleteMessage(id: String) {
        synchronized(messages) {
            messages.removeAll { it.id == id }
        }
    }
    
    /**
     * Clear all messages
     */
    fun clearAll() {
        synchronized(messages) {
            messages.clear()
        }
    }
    
    /**
     * Register listener for new messages
     */
    fun addMessageListener(listener: (IncomingSms) -> Unit) {
        synchronized(listeners) {
            listeners.add(listener)
        }
    }
    
    /**
     * Remove listener
     */
    fun removeMessageListener(listener: (IncomingSms) -> Unit) {
        synchronized(listeners) {
            listeners.remove(listener)
        }
    }
    
    /**
     * Get message count
     */
    fun getMessageCount(): Int {
        synchronized(messages) {
            return messages.size
        }
    }
    
    /**
     * Get unread count
     */
    fun getUnreadCount(): Int {
        synchronized(messages) {
            return messages.count { !it.isRead }
        }
    }
}
