package com.telefoncek.silentsms.detector;

import android.util.Log;

import java.io.BufferedReader;
import java.io.File;
import java.io.InputStreamReader;

/**
 * Utility class to check if the device has root access.
 * This is required for accessing Android system logs to detect Type-0 SMS messages.
 */
public class RootChecker {
    private static final String TAG = "RootChecker";

    /**
     * Check if the device has root access by attempting to execute 'su' command
     * @return true if root access is available, false otherwise
     */
    public static boolean isRootAvailable() {
        // Check for common root binary locations
        String[] rootPaths = {
            "/system/app/Superuser.apk",
            "/sbin/su",
            "/system/bin/su",
            "/system/xbin/su",
            "/data/local/xbin/su",
            "/data/local/bin/su",
            "/system/sd/xbin/su",
            "/system/bin/failsafe/su",
            "/data/local/su",
            "/su/bin/su"
        };

        for (String path : rootPaths) {
            if (new File(path).exists()) {
                Log.d(TAG, "Root binary found at: " + path);
                return canExecuteSuCommand();
            }
        }

        return canExecuteSuCommand();
    }

    /**
     * Attempt to execute the 'su' command to verify root access
     * @return true if su command can be executed successfully, false otherwise
     */
    private static boolean canExecuteSuCommand() {
        Process process = null;
        BufferedReader reader = null;
        try {
            process = Runtime.getRuntime().exec("su -c id");
            reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            String output = reader.readLine();
            
            // Wait for process to complete
            int exitValue = process.waitFor();
            
            // If the command executed successfully and output contains 'uid=0' (root user)
            if (exitValue == 0 && output != null && output.toLowerCase().contains("uid=0")) {
                Log.d(TAG, "Root access verified: " + output);
                return true;
            }
            
            Log.d(TAG, "Root access check failed. Exit value: " + exitValue + ", Output: " + output);
            return false;
        } catch (Exception e) {
            Log.e(TAG, "Error checking root access", e);
            return false;
        } finally {
            try {
                if (reader != null) {
                    reader.close();
                }
                if (process != null) {
                    process.destroy();
                }
            } catch (Exception e) {
                Log.e(TAG, "Error closing resources", e);
            }
        }
    }

    /**
     * Get a user-friendly message explaining root access status
     * @return String message for display to user
     */
    public static String getRootStatusMessage() {
        if (isRootAvailable()) {
            return "Root access detected. Type-0 SMS detection is available.";
        } else {
            return "Root access not available. Type-0 SMS detection requires a rooted device.";
        }
    }
}
