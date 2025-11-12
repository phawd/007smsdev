package com.telefoncek.silentsms.detector;

import org.junit.Test;
import static org.junit.Assert.*;

/**
 * Unit tests for RootChecker utility class
 */
public class RootCheckerTest {

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
