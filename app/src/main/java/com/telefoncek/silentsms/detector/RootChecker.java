package com.telefoncek.zerosms.detector;

import android.util.Log;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;

/**
 * Utility class to check if the device has root access.
 * This is required for accessing Android system logs to detect Type-0 SMS messages.
 */
public class RootChecker {
    private static final String TAG = "RootChecker";

    public interface Logger {
        void d(String tag, String msg);
        void e(String tag, String msg, Throwable tr);
        void w(String tag, String msg);
    }

    private static Logger logger = new Logger() {
        @Override
        public void d(String tag, String msg) { Log.d(tag, msg); }
        @Override
        public void e(String tag, String msg, Throwable tr) { Log.e(tag, msg, tr); }
        @Override
        public void w(String tag, String msg) { Log.w(tag, msg); }
    };

    public static void setLogger(Logger newLogger) {
        logger = newLogger;
    }

    public interface CommandExecutor {
        Process execute(String command) throws IOException;
    }

    private static CommandExecutor commandExecutor = new CommandExecutor() {
        @Override
        public Process execute(String command) throws IOException {
            return Runtime.getRuntime().exec(command);
        }
    };

    public static void setCommandExecutor(CommandExecutor executor) {
        commandExecutor = executor;
    }

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
                logger.d(TAG, "Root binary found at: " + path);
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
            process = commandExecutor.execute("su -c id");
            reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            String output = reader.readLine();
            
            // Wait for process to complete
            int exitValue = process.waitFor();
            
            // If the command executed successfully and output contains 'uid=0' (root user)
            if (exitValue == 0 && output != null && output.toLowerCase().contains("uid=0")) {
                logger.d(TAG, "Root access verified: " + output);
                return true;
            }
            
            logger.d(TAG, "Root access check failed. Exit value: " + exitValue + ", Output: " + output);
            return false;
        } catch (Exception e) {
            logger.e(TAG, "Error checking root access", e);
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
                logger.e(TAG, "Error closing resources", e);
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
