package com.smstest.app

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.zerosms.testing.core.root.RootAccessManager
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class RootAndModemTest {

    private lateinit var rootAccessManager: RootAccessManager

    @Before
    fun setup() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        rootAccessManager = RootAccessManager(context)
    }

    @Test
    fun testRootAccess() {
        val isRooted = rootAccessManager.isRooted()
        assertTrue("Device should be rooted for this test", isRooted)
    }
}
