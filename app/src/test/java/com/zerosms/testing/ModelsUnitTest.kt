package com.zerosms.testing

import com.zerosms.testing.core.model.MessageType
import com.zerosms.testing.core.model.SmsEncoding
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test

class ModelsUnitTest {
    @Test
    fun messageType_and_encoding_defaults() {
        val types = MessageType.values()
        assertTrue(types.isNotEmpty())

        val enc = SmsEncoding.AUTO
        assertNotNull(enc)
    }
}
