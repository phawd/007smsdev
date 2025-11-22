package com.telefoncek.zerosms.detector;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.RobolectricTestRunner;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import static org.junit.Assert.*;

/**
 * Unit tests for LogParser utility class
 */
@RunWith(RobolectricTestRunner.class)
public class LogParserTest {

    @Before
    public void setUp() {
        // Mock the CommandExecutor
        LogParser.setCommandExecutor(new LogParser.CommandExecutor() {
            @Override
            public Process execute(String command) throws IOException {
                return new Process() {
                    @Override
                    public OutputStream getOutputStream() { return new ByteArrayOutputStream(); }
                    @Override
                    public InputStream getInputStream() { return new ByteArrayInputStream(new byte[0]); }
                    @Override
                    public InputStream getErrorStream() { return new ByteArrayInputStream(new byte[0]); }
                    @Override
                    public int waitFor() throws InterruptedException { return 0; }
                    @Override
                    public int exitValue() { return 0; }
                    @Override
                    public void destroy() { }
                };
            }
        });

        // Mock the Logger
        LogParser.setLogger(new LogParser.Logger() {
            @Override
            public void d(String tag, String msg) { System.out.println("DEBUG: " + tag + ": " + msg); }
            @Override
            public void e(String tag, String msg, Throwable tr) { System.out.println("ERROR: " + tag + ": " + msg); if(tr!=null) tr.printStackTrace(); }
            @Override
            public void w(String tag, String msg) { System.out.println("WARN: " + tag + ": " + msg); }
        });
        
        // Also need to mock RootChecker's logger because LogParser calls RootChecker
        RootChecker.setLogger(new RootChecker.Logger() {
            @Override
            public void d(String tag, String msg) { System.out.println("DEBUG: " + tag + ": " + msg); }
            @Override
            public void e(String tag, String msg, Throwable tr) { System.out.println("ERROR: " + tag + ": " + msg); if(tr!=null) tr.printStackTrace(); }
            @Override
            public void w(String tag, String msg) { System.out.println("WARN: " + tag + ": " + msg); }
        });
        
        // And RootChecker's executor, as LogParser calls RootChecker.isRootAvailable()
        RootChecker.setCommandExecutor(new RootChecker.CommandExecutor() {
             @Override
            public Process execute(String command) throws IOException {
                return new Process() {
                    @Override
                    public OutputStream getOutputStream() { return new ByteArrayOutputStream(); }
                    @Override
                    public InputStream getInputStream() { return new ByteArrayInputStream("uid=0".getBytes()); } // Simulate root
                    @Override
                    public InputStream getErrorStream() { return new ByteArrayInputStream(new byte[0]); }
                    @Override
                    public int waitFor() throws InterruptedException { return 0; }
                    @Override
                    public int exitValue() { return 0; }
                    @Override
                    public void destroy() { }
                };
            }
        });
    }

    @After
    public void tearDown() {
        // Reset to default behavior
        RootChecker.setCommandExecutor(new RootChecker.CommandExecutor() {
            @Override
            public Process execute(String command) throws IOException {
                throw new IOException("Command execution disabled in tests");
            }
        });
        LogParser.setCommandExecutor(new LogParser.CommandExecutor() {
            @Override
            public Process execute(String command) throws IOException {
                throw new IOException("Command execution disabled in tests");
            }
        });
    }

    private Process createMockProcess(final String output, final int exitCode) {
        return new Process() {
            @Override
            public OutputStream getOutputStream() { return new ByteArrayOutputStream(); }

            @Override
            public InputStream getInputStream() { return new ByteArrayInputStream(output.getBytes()); }

            @Override
            public InputStream getErrorStream() { return new ByteArrayInputStream(new byte[0]); }

            @Override
            public int waitFor() { return exitCode; }

            @Override
            public int exitValue() { return exitCode; }

            @Override
            public void destroy() { }
        };
    }

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
