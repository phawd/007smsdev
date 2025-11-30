package com.zerosms.testing.core.mms

import android.content.Context
import android.net.Uri
import com.zerosms.testing.core.model.*
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.withContext
import java.io.ByteArrayOutputStream
import java.io.File
import java.util.Date

/**
 * MMS Manager implementing MMS specifications
 * Supports OMA MMS Encapsulation Protocol, WAP-209-MMSEncapsulation
 */
class MmsManagerWrapper(private val context: Context) {
    
    private val _messageStatus = MutableStateFlow<Map<String, DeliveryStatus>>(emptyMap())
    val messageStatus: Flow<Map<String, DeliveryStatus>> = _messageStatus.asStateFlow()
    
    companion object {
        const val MMS_MAX_SIZE = 300 * 1024  // 300KB typical carrier limit
        const val MMS_MAX_MESSAGE_SIZE = 600 * 1024  // 600KB extended limit
        
        // MIME types per RFC 2046
        const val MIME_TEXT_PLAIN = "text/plain"
        const val MIME_TEXT_HTML = "text/html"
        const val MIME_IMAGE_JPEG = "image/jpeg"
        const val MIME_IMAGE_PNG = "image/png"
        const val MIME_IMAGE_GIF = "image/gif"
        const val MIME_VIDEO_MP4 = "video/mp4"
        const val MIME_VIDEO_3GPP = "video/3gpp"
        const val MIME_AUDIO_AMR = "audio/amr"
        const val MIME_AUDIO_MP3 = "audio/mp3"
        const val MIME_TEXT_VCARD = "text/x-vcard"
        const val MIME_MULTIPART_MIXED = "multipart/mixed"
        const val MIME_MULTIPART_RELATED = "multipart/related"
    }
    
    /**
     * Send MMS message with attachments
     * Implements OMA MMS Encapsulation Protocol
     */
    suspend fun sendMms(message: Message): Result<String> = withContext(Dispatchers.IO) {
        try {
            val messageId = message.id
            
            // Validate message
            val validation = validateMmsMessage(message)
            if (!validation.isValid) {
                return@withContext Result.failure(
                    Exception("MMS validation failed: ${validation.errors.joinToString()}")
                )
            }
            
            // Build MMS PDU
            val mmsPdu = buildMmsPdu(message)
            
            // Send via carrier MMS gateway
            sendMmsPdu(message.destination, mmsPdu, messageId)
            
            updateStatus(messageId, DeliveryStatus.SENT)
            Result.success(messageId)
        } catch (e: Exception) {
            Result.failure(e)
        }
    }
    
    /**
     * Validate MMS message per OMA specifications
     */
    private fun validateMmsMessage(message: Message): ValidationResult {
        val errors = mutableListOf<String>()
        
        // Check total size
        val totalSize = calculateMmsSize(message)
        if (totalSize > MMS_MAX_MESSAGE_SIZE) {
            errors.add("Message size ($totalSize bytes) exceeds limit ($MMS_MAX_MESSAGE_SIZE bytes)")
        }
        
        // Validate attachments
        message.attachments.forEach { attachment ->
            if (!isValidMimeType(attachment.mimeType)) {
                errors.add("Unsupported MIME type: ${attachment.mimeType}")
            }
            
            if (attachment.size > MMS_MAX_SIZE) {
                errors.add("Attachment ${attachment.fileName} exceeds size limit")
            }
        }
        
        // Check recipient format (E.164 format recommended)
        if (!isValidPhoneNumber(message.destination)) {
            errors.add("Invalid recipient phone number format")
        }
        
        return ValidationResult(
            isValid = errors.isEmpty(),
            errors = errors
        )
    }
    
    /**
     * Calculate total MMS message size
     */
    private fun calculateMmsSize(message: Message): Long {
        var totalSize = 0L
        
        // Add text content size
        message.body?.let { totalSize += it.toByteArray().size }
        message.subject?.let { totalSize += it.toByteArray().size }
        
        // Add attachment sizes
        message.attachments.forEach { attachment ->
            totalSize += attachment.size
        }
        
        // Add estimated headers overhead (typically 200-500 bytes)
        totalSize += 500
        
        return totalSize
    }
    
    /**
     * Build MMS PDU (Protocol Data Unit)
     * Implements WSP encoding per WAP-230-WSP
     */
    private fun buildMmsPdu(message: Message): ByteArray {
        val outputStream = ByteArrayOutputStream()
        
        // MMS Message Type: m-send-req (0x80)
        outputStream.write(0x8C)  // X-Mms-Message-Type
        outputStream.write(0x80)  // Value: m-send-req
        
        // Transaction ID
        outputStream.write(0x98)  // X-Mms-Transaction-ID
        writeTextString(outputStream, message.id)
        
        // MMS Version: 1.3 (0x13)
        outputStream.write(0x8D)  // X-Mms-MMS-Version
        outputStream.write(0x13)
        
        // To field
        outputStream.write(0x97)  // To
        writeAddressString(outputStream, message.destination)
        
        // Subject
        message.subject?.let {
            outputStream.write(0x96)  // Subject
            writeTextString(outputStream, it)
        }
        
        // Delivery report
        if (message.deliveryReport) {
            outputStream.write(0x86)  // X-Mms-Delivery-Report
            outputStream.write(0x80)  // Yes
        }
        
        // Read report
        if (message.readReport) {
            outputStream.write(0x90)  // X-Mms-Read-Report
            outputStream.write(0x80)  // Yes
        }
        
        // Priority
        outputStream.write(0x8F)  // X-Mms-Priority
        outputStream.write(when (message.priority) {
            Priority.LOW -> 0x82
            Priority.NORMAL -> 0x81
            Priority.HIGH, Priority.URGENT -> 0x80
        })
        
        // Content Type: multipart/related
        outputStream.write(0x84)  // Content-Type
        writeContentType(outputStream, MIME_MULTIPART_RELATED)
        
        // Message body (text)
        message.body?.let { body ->
            writeMmsPart(outputStream, body.toByteArray(), MIME_TEXT_PLAIN, "text_0")
        }
        
        // Attachments
        message.attachments.forEachIndexed { index, attachment ->
            val attachmentData = readAttachmentData(attachment.uri)
            writeMmsPart(
                outputStream,
                attachmentData,
                attachment.mimeType,
                attachment.contentId ?: "attachment_$index"
            )
        }
        
        return outputStream.toByteArray()
    }
    
    /**
     * Write text string to MMS PDU
     */
    private fun writeTextString(stream: ByteArrayOutputStream, text: String) {
        val bytes = text.toByteArray()
        stream.write(bytes)
        stream.write(0x00)  // Null terminator
    }
    
    /**
     * Write address string (phone number) to MMS PDU
     */
    private fun writeAddressString(stream: ByteArrayOutputStream, address: String) {
        val addressType = 0x81  // PLMN (phone number)
        stream.write(addressType)
        writeTextString(stream, address)
    }
    
    /**
     * Write content type to MMS PDU
     */
    private fun writeContentType(stream: ByteArrayOutputStream, mimeType: String) {
        val bytes = mimeType.toByteArray()
        stream.write(bytes.size)
        stream.write(bytes)
    }
    
    /**
     * Write MMS part (text or attachment)
     */
    private fun writeMmsPart(
        stream: ByteArrayOutputStream,
        data: ByteArray,
        mimeType: String,
        contentId: String
    ) {
        // Part header length
        val headerStream = ByteArrayOutputStream()
        
        // Content-Type
        writeContentType(headerStream, mimeType)
        
        // Content-ID
        headerStream.write(0xC0)  // Content-ID
        writeTextString(headerStream, "<$contentId>")
        
        val headerData = headerStream.toByteArray()
        
        // Write header length
        writeUintVar(stream, headerData.size.toLong())
        
        // Write data length
        writeUintVar(stream, data.size.toLong())
        
        // Write header
        stream.write(headerData)
        
        // Write data
        stream.write(data)
    }
    
    /**
     * Write variable-length unsigned integer (WSP encoding)
     */
    private fun writeUintVar(stream: ByteArrayOutputStream, value: Long) {
        var v = value
        val bytes = mutableListOf<Byte>()
        
        do {
            bytes.add(0, (v and 0x7F).toByte())
            v = v shr 7
        } while (v > 0)
        
        for (i in 0 until bytes.size - 1) {
            stream.write((bytes[i].toInt() or 0x80))
        }
        stream.write(bytes.last().toInt())
    }
    
    /**
     * Read attachment data from URI
     */
    private fun readAttachmentData(uri: String): ByteArray {
        return try {
            val contentUri = Uri.parse(uri)
            context.contentResolver.openInputStream(contentUri)?.use { inputStream ->
                inputStream.readBytes()
            } ?: byteArrayOf()
        } catch (e: Exception) {
            byteArrayOf()
        }
    }
    
    /**
     * Send MMS PDU via carrier gateway
     * Note: This is a simplified implementation
     * Production use requires carrier-specific APN configuration
     */
    private fun sendMmsPdu(destination: String, pdu: ByteArray, messageId: String) {
        // In a real implementation, this would:
        // 1. Configure APN settings for MMS
        // 2. Establish HTTP connection to carrier MMSC
        // 3. POST the PDU using WAP protocol
        // 4. Handle response and delivery reports
        
        // For testing purposes, we simulate the send
        updateStatus(messageId, DeliveryStatus.SENT)
    }
    
    /**
     * Validate MIME type per RFC 2046
     */
    private fun isValidMimeType(mimeType: String): Boolean {
        val validTypes = setOf(
            MIME_TEXT_PLAIN, MIME_TEXT_HTML,
            MIME_IMAGE_JPEG, MIME_IMAGE_PNG, MIME_IMAGE_GIF,
            MIME_VIDEO_MP4, MIME_VIDEO_3GPP,
            MIME_AUDIO_AMR, MIME_AUDIO_MP3,
            MIME_TEXT_VCARD
        )
        return mimeType in validTypes || mimeType.startsWith("image/") || 
               mimeType.startsWith("video/") || mimeType.startsWith("audio/")
    }
    
    /**
     * Validate phone number format (E.164 recommended)
     */
    private fun isValidPhoneNumber(number: String): Boolean {
        // Basic validation - can be enhanced with libphonenumber
        val cleanNumber = number.replace(Regex("[^0-9+]"), "")
        return cleanNumber.isNotEmpty() && cleanNumber.length in 7..15
    }
    
    private fun updateStatus(messageId: String, status: DeliveryStatus) {
        val currentMap = _messageStatus.value.toMutableMap()
        currentMap[messageId] = status
        _messageStatus.value = currentMap
    }
}

/**
 * Validation result model
 */
data class ValidationResult(
    val isValid: Boolean,
    val errors: List<String>
)
