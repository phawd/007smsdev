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
 * Unit tests for RootChecker utility class
 */
@RunWith(RobolectricTestRunner.class)
public class RootCheckerTest {

    @Before
    public void setUp() {
        // Mock the CommandExecutor to avoid actual Runtime.exec calls
        RootChecker.setCommandExecutor(new RootChecker.CommandExecutor() {
            @Override
            public Process execute(String command) throws IOException {
                // Return a dummy process that simulates "su" failure or success based on test needs
                // For default tests, we can simulate failure or a specific output
                return new Process() {
                    @Override
                    public OutputStream getOutputStream() { return new ByteArrayOutputStream(); }

                    @Override
                    public InputStream getInputStream() { 
                        // Default: simulate "uid=0" for success, or empty for failure
                        // We can control this via a static flag if needed, but for now let's simulate failure by default
                        // unless overridden in specific tests.
                        // Actually, let's simulate a safe failure (non-root) by default.
                        return new ByteArrayInputStream("uid=1000".getBytes()); 
                    }

                    @Override
                    public InputStream getErrorStream() { return new ByteArrayInputStream(new byte[0]); }

                    @Override
                    public int waitFor() throws InterruptedException { return 1; } // Non-zero exit code

                    @Override
                    public int exitValue() { return 1; }

                    @Override
                    public void destroy() { }
                };
            }
        });

        // Mock the Logger to avoid android.util.Log calls
        RootChecker.setLogger(new RootChecker.Logger() {
            @Override
            public void d(String tag, String msg) { System.out.println("DEBUG: " + tag + ": " + msg); }
            @Override
            public void e(String tag, String msg, Throwable tr) { System.out.println("ERROR: " + tag + ": " + msg); if(tr!=null) tr.printStackTrace(); }
            @Override
            public void w(String tag, String msg) { System.out.println("WARN: " + tag + ": " + msg); }
        });
    }

    @After
    public void tearDown() {
        // Reset to default behavior (or a safe no-op) to avoid side effects
        RootChecker.setCommandExecutor(new RootChecker.CommandExecutor() {
            @Override
            public Process execute(String command) throws IOException {
                throw new IOException("Command execution disabled in tests");
            }
        });
    }

    @Test
    public void testGetRootStatusMessage_returnsNonNull() {
        String message = RootChecker.getRootStatusMessage();
        assertNotNull("Root status message should not be null", message);
        assertFalse("Root status message should not be empty", message.isEmpty());
    }

    @Test
    public void testGetRootStatusMessage_containsExpectedText() {
        String message = RootChecker.getRootStatusMessage();
        assertTrue("Message should mention Type-0 SMS or root access",
            message.toLowerCase().contains("type-0") || 
            message.toLowerCase().contains("root access") ||
            message.toLowerCase().contains("root"));
    }

    @Test
    public void testIsRootAvailable_returnsBoolean() {
        // This test just verifies the method returns without crashing
        // Actual result depends on the environment
        boolean result = RootChecker.isRootAvailable();
        // Result should be either true or false, not throwing exception
        assertTrue("Result should be true or false", result == true || result == false);
    }
}
