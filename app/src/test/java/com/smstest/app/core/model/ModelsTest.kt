package com.smstest.app.core.model

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.Date

/**
 * Unit tests for core data models.
 */
class ModelsTest {

    @Test
    fun `Message defaults are correct`() {
        val msg = Message(
            id = "test-001",
            type = MessageType.SMS_TEXT,
            destination = "+15550001234"
        )

        assertEquals("test-001", msg.id)
        assertEquals(MessageType.SMS_TEXT, msg.type)
        assertEquals("+15550001234", msg.destination)
        assertEquals(SmsEncoding.AUTO, msg.encoding)
        assertEquals(MessageClass.NONE, msg.messageClass)
        assertEquals(Priority.NORMAL, msg.priority)
        assertEquals(DeliveryStatus.PENDING, msg.status)
        assertEquals(1, msg.parts)
        assertTrue(msg.attachments.isEmpty())
    }

    @Test
    fun `Message with custom fields retains values`() {
        val ts = Date()
        val msg = Message(
            id = "test-002",
            type = MessageType.SMS_FLASH,
            destination = "+15550001234",
            body = "Flash!",
            encoding = SmsEncoding.GSM_7BIT,
            messageClass = MessageClass.CLASS_0,
            priority = Priority.URGENT,
            deliveryReport = true,
            timestamp = ts
        )

        assertEquals(MessageType.SMS_FLASH, msg.type)
        assertEquals("Flash!", msg.body)
        assertEquals(SmsEncoding.GSM_7BIT, msg.encoding)
        assertEquals(MessageClass.CLASS_0, msg.messageClass)
        assertEquals(Priority.URGENT, msg.priority)
        assertTrue(msg.deliveryReport)
        assertEquals(ts, msg.timestamp)
    }

    @Test
    fun `DeliveryStatus transitions cover expected values`() {
        val statuses = DeliveryStatus.values()
        val names = statuses.map { it.name }
        assertTrue(names.contains("PENDING"))
        assertTrue(names.contains("SENT"))
        assertTrue(names.contains("DELIVERED"))
        assertTrue(names.contains("FAILED"))
    }

    @Test
    fun `MessageType covers SMS MMS and RCS families`() {
        val types = MessageType.values().map { it.name }
        assertTrue(types.any { it.startsWith("SMS_") })
        assertTrue(types.any { it.startsWith("MMS_") })
        assertTrue(types.any { it.startsWith("RCS_") })
    }

    @Test
    fun `SmsEncoding AUTO is available`() {
        assertNotNull(SmsEncoding.AUTO)
    }
}
