package com.zerosms.testing

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.zerosms.testing.core.sms.SmsManagerWrapper
import com.zerosms.testing.core.model.SmsEncoding
import org.junit.Assert.assertEquals
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class SmsManagerWrapperInstrumentedTest {
    @Test
    fun calculateSmsInfo_gsm_and_ucs2() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val wrapper = SmsManagerWrapper(context)

        val ascii = "Hello, ZeroSMS!"
        val info1 = wrapper.calculateSmsInfo(ascii)
        assertEquals(1, info1.parts)
        assertEquals(SmsEncoding.GSM_7BIT, info1.encoding)

        val unicode = "こんにちは世界" // Non-ASCII Japanese text
        val info2 = wrapper.calculateSmsInfo(unicode)
        assertEquals(SmsEncoding.UCS2, info2.encoding)
        assertEquals(unicode.length, info2.totalChars)
    }
}
