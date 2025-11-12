package com.telefoncek.silentsms.detector;

import android.util.Log;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Utility class to parse Android system logs for Type-0 SMS message indicators.
 * Requires root access to read system logs.
 */
public class LogParser {
    private static final String TAG = "LogParser";
    
    // Pattern to match Type-0 SMS log entries
    private static final String TYPE0_SMS_PATTERN = "GsmInboundSmsHandler.*Received short message type 0";
    private static final Pattern pattern = Pattern.compile(TYPE0_SMS_PATTERN, Pattern.CASE_INSENSITIVE);
    
    // Keep track of last seen log timestamp to avoid duplicate detections
    private static String lastTimestamp = "";

    /**
     * Scan system logs for Type-0 SMS indicators
     * @param sinceDuration Duration to look back in logs (e.g., "1m" for 1 minute)
     * @return List of log entries matching Type-0 SMS pattern
     */
    public static List<String> scanLogsForType0Sms(String sinceDuration) {
        List<String> detectedMessages = new ArrayList<>();
        
        if (!RootChecker.isRootAvailable()) {
            Log.w(TAG, "Root access not available. Cannot scan logs.");
            return detectedMessages;
        }

        Process process = null;
        BufferedReader reader = null;
        BufferedReader errorReader = null;
        
        try {
            // Execute logcat command with root permissions
            // -t: specify time duration
            // -v time: include timestamps
            // *:S: silence all logs except what we filter
            String command = "su -c logcat -t " + sinceDuration + " -v time";
            process = Runtime.getRuntime().exec(command);
            
            reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            errorReader = new BufferedReader(new InputStreamReader(process.getErrorStream()));
            
            String line;
            while ((line = reader.readLine()) != null) {
                Matcher matcher = pattern.matcher(line);
                if (matcher.find()) {
                    // Extract timestamp from the log line to avoid duplicates
                    String timestamp = extractTimestamp(line);
                    if (!timestamp.equals(lastTimestamp)) {
                        Log.d(TAG, "Type-0 SMS detected: " + line);
                        detectedMessages.add(line);
                        lastTimestamp = timestamp;
                    }
                }
            }
            
            // Log any errors
            String errorLine;
            while ((errorLine = errorReader.readLine()) != null) {
                Log.e(TAG, "Logcat error: " + errorLine);
            }
            
        } catch (Exception e) {
            Log.e(TAG, "Error scanning logs for Type-0 SMS", e);
        } finally {
            try {
                if (reader != null) {
                    reader.close();
                }
                if (errorReader != null) {
                    errorReader.close();
                }
                if (process != null) {
                    process.destroy();
                }
            } catch (Exception e) {
                Log.e(TAG, "Error closing resources", e);
            }
        }
        
        return detectedMessages;
    }

    /**
     * Extract timestamp from log line to track unique messages
     * @param logLine The log line to parse
     * @return Timestamp string or empty if not found
     */
    private static String extractTimestamp(String logLine) {
        try {
            // Android log format typically starts with date and time
            // Format: MM-DD HH:MM:SS.mmm
            if (logLine.length() > 18) {
                return logLine.substring(0, 18).trim();
            }
        } catch (Exception e) {
            Log.e(TAG, "Error extracting timestamp", e);
        }
        return "";
    }

    /**
     * Parse a Type-0 SMS log entry to extract useful information
     * @param logEntry The log entry to parse
     * @return Formatted string with extracted information
     */
    public static String parseType0SmsLogEntry(String logEntry) {
        try {
            // Extract timestamp
            String timestamp = extractTimestamp(logEntry);
            
            // Basic parsing - in a real implementation, you might extract more details
            // such as message ID, sender info if available in logs
            return "Type-0 SMS detected at " + timestamp;
        } catch (Exception e) {
            Log.e(TAG, "Error parsing log entry", e);
            return "Type-0 SMS detected (parsing error)";
        }
    }

    /**
     * Clear the last timestamp tracker (useful for testing or resetting state)
     */
    public static void resetTimestampTracker() {
        lastTimestamp = "";
    }

    /**
     * Check if log scanning is available (root access + log permissions)
     * @return true if log scanning is possible, false otherwise
     */
    public static boolean isLogScanningAvailable() {
        if (!RootChecker.isRootAvailable()) {
            return false;
        }

        // Try to read logs briefly to check if it works
        Process process = null;
        try {
            process = Runtime.getRuntime().exec("su -c logcat -d -t 1");
            int exitValue = process.waitFor();
            return exitValue == 0;
        } catch (Exception e) {
            Log.e(TAG, "Error checking log scanning availability", e);
            return false;
        } finally {
            if (process != null) {
                process.destroy();
            }
        }
    }
}
