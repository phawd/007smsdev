package com.telefoncek.silentsms.detector;

import org.junit.Test;
import static org.junit.Assert.*;

/**
 * Unit tests for LogParser utility class
 */
public class LogParserTest {

    @Test
    public void testParseType0SmsLogEntry_withValidEntry() {
        String logEntry = "11-12 10:30:45.123 D/GsmInboundSmsHandler: Received short message type 0";
        String result = LogParser.parseType0SmsLogEntry(logEntry);
        
        assertNotNull("Parsed result should not be null", result);
        assertFalse("Parsed result should not be empty", result.isEmpty());
        assertTrue("Result should mention Type-0 SMS", result.contains("Type-0 SMS"));
    }

    @Test
    public void testParseType0SmsLogEntry_withEmptyEntry() {
        String logEntry = "";
        String result = LogParser.parseType0SmsLogEntry(logEntry);
        
        assertNotNull("Parsed result should not be null even for empty input", result);
    }

    @Test
    public void testParseType0SmsLogEntry_withNullEntry() {
        String result = LogParser.parseType0SmsLogEntry(null);
        
        assertNotNull("Parsed result should not be null even for null input", result);
    }

    @Test
    public void testScanLogsForType0Sms_returnsNonNull() {
        // This test verifies the method returns a list (even if empty)
        // Actual scanning requires root and won't work in unit test environment
        var result = LogParser.scanLogsForType0Sms("1m");
        
        assertNotNull("Scan result should not be null", result);
    }

    @Test
    public void testResetTimestampTracker_doesNotThrow() {
        // Verify the method executes without throwing exceptions
        try {
            LogParser.resetTimestampTracker();
            assertTrue("resetTimestampTracker should not throw exception", true);
        } catch (Exception e) {
            fail("resetTimestampTracker should not throw exception: " + e.getMessage());
        }
    }

    @Test
    public void testIsLogScanningAvailable_returnsBoolean() {
        // This test verifies the method returns without crashing
        // Actual result depends on the environment
        boolean result = LogParser.isLogScanningAvailable();
        // Result should be either true or false, not throwing exception
        assertTrue("Result should be true or false", result == true || result == false);
    }
}
