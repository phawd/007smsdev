package com.telefoncek.silentsms.detector;

import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.app.Service;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.graphics.Color;
import android.os.Build;
import android.os.Handler;
import android.os.IBinder;
import android.os.Looper;
import android.util.Log;

import androidx.annotation.Nullable;
import androidx.core.app.NotificationCompat;

import java.util.List;

/**
 * Background service that monitors Android system logs for Type-0 SMS messages.
 * Requires root access to function properly.
 */
public class Type0SmsMonitorService extends Service {
    private static final String TAG = "Type0SmsMonitor";
    private static final String CHANNEL_ID = "com.telefoncek.silentsms.detector.type0";
    private static final int SCAN_INTERVAL_MS = 30000; // 30 seconds
    private static final String PREF_NAME = "Type0SmsPreferences";
    private static final String PREF_MONITORING_ENABLED = "monitoring_enabled";
    
    private Handler handler;
    private Runnable scanRunnable;
    private boolean isMonitoring = false;

    @Override
    public void onCreate() {
        super.onCreate();
        Log.d(TAG, "Service created");
        
        handler = new Handler(Looper.getMainLooper());
        
        scanRunnable = new Runnable() {
            @Override
            public void run() {
                if (isMonitoring) {
                    scanForType0Sms();
                    handler.postDelayed(this, SCAN_INTERVAL_MS);
                }
            }
        };
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        Log.d(TAG, "Service started");
        
        // Check if root access is available
        if (!RootChecker.isRootAvailable()) {
            Log.w(TAG, "Root access not available. Stopping service.");
            notifyRootAccessRequired();
            stopSelf();
            return START_NOT_STICKY;
        }

        // Check if log scanning is available
        if (!LogParser.isLogScanningAvailable()) {
            Log.w(TAG, "Log scanning not available. Stopping service.");
            notifyLogAccessFailed();
            stopSelf();
            return START_NOT_STICKY;
        }

        // Start monitoring
        if (!isMonitoring) {
            isMonitoring = true;
            handler.post(scanRunnable);
            Log.d(TAG, "Monitoring started");
        }

        return START_STICKY;
    }

    /**
     * Scan logs for Type-0 SMS messages
     */
    private void scanForType0Sms() {
        try {
            // Scan logs from the last scan interval
            String sinceDuration = (SCAN_INTERVAL_MS / 1000) + "s";
            List<String> detectedMessages = LogParser.scanLogsForType0Sms(sinceDuration);
            
            if (!detectedMessages.isEmpty()) {
                Log.d(TAG, "Detected " + detectedMessages.size() + " Type-0 SMS message(s)");
                for (String message : detectedMessages) {
                    notifyType0SmsDetected(message);
                }
            }
        } catch (Exception e) {
            Log.e(TAG, "Error during log scanning", e);
        }
    }

    /**
     * Send notification when Type-0 SMS is detected
     */
    private void notifyType0SmsDetected(String logEntry) {
        NotificationManager notificationManager = 
            (NotificationManager) getSystemService(Context.NOTIFICATION_SERVICE);
        
        if (notificationManager == null) {
            return;
        }

        // Create notification channel for Android O and above
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            NotificationChannel channel = new NotificationChannel(
                CHANNEL_ID,
                "Type-0 SMS Detection",
                NotificationManager.IMPORTANCE_HIGH
            );
            channel.setDescription("Notifications for Type-0 SMS messages detected via log scanning");
            channel.enableLights(true);
            channel.setLightColor(Color.YELLOW);
            channel.enableVibration(true);
            notificationManager.createNotificationChannel(channel);
        }

        // Create intent to open the app
        Intent intent = new Intent(this, MainActivity.class);
        intent.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_CLEAR_TASK);
        PendingIntent pendingIntent = PendingIntent.getActivity(
            this, 0, intent, PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_MUTABLE
        );

        // Parse the log entry for display
        String displayText = LogParser.parseType0SmsLogEntry(logEntry);

        // Build notification
        NotificationCompat.Builder builder = new NotificationCompat.Builder(this, CHANNEL_ID)
            .setSmallIcon(R.drawable.main_icon)
            .setContentTitle("Type-0 SMS Detected!")
            .setContentText(displayText)
            .setStyle(new NotificationCompat.BigTextStyle()
                .bigText("A Type-0 SMS message was detected through log analysis. " +
                        "This type of message is completely hidden but was detected via root access. " +
                        "Time: " + displayText))
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .setContentIntent(pendingIntent)
            .setAutoCancel(true)
            .setVibrate(new long[]{0, 500, 200, 500});

        notificationManager.notify((int) System.currentTimeMillis(), builder.build());
    }

    /**
     * Notify user that root access is required
     */
    private void notifyRootAccessRequired() {
        NotificationManager notificationManager = 
            (NotificationManager) getSystemService(Context.NOTIFICATION_SERVICE);
        
        if (notificationManager == null) {
            return;
        }

        // Create notification channel
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            NotificationChannel channel = new NotificationChannel(
                CHANNEL_ID,
                "Type-0 SMS Detection",
                NotificationManager.IMPORTANCE_DEFAULT
            );
            notificationManager.createNotificationChannel(channel);
        }

        NotificationCompat.Builder builder = new NotificationCompat.Builder(this, CHANNEL_ID)
            .setSmallIcon(R.drawable.main_icon)
            .setContentTitle("Root Access Required")
            .setContentText("Type-0 SMS monitoring requires root access on your device.")
            .setPriority(NotificationCompat.PRIORITY_DEFAULT)
            .setAutoCancel(true);

        notificationManager.notify(999, builder.build());
    }

    /**
     * Notify user that log access failed
     */
    private void notifyLogAccessFailed() {
        NotificationManager notificationManager = 
            (NotificationManager) getSystemService(Context.NOTIFICATION_SERVICE);
        
        if (notificationManager == null) {
            return;
        }

        // Create notification channel
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            NotificationChannel channel = new NotificationChannel(
                CHANNEL_ID,
                "Type-0 SMS Detection",
                NotificationManager.IMPORTANCE_DEFAULT
            );
            notificationManager.createNotificationChannel(channel);
        }

        NotificationCompat.Builder builder = new NotificationCompat.Builder(this, CHANNEL_ID)
            .setSmallIcon(R.drawable.main_icon)
            .setContentTitle("Log Access Failed")
            .setContentText("Unable to access system logs for Type-0 SMS monitoring.")
            .setPriority(NotificationCompat.PRIORITY_DEFAULT)
            .setAutoCancel(true);

        notificationManager.notify(998, builder.build());
    }

    @Override
    public void onDestroy() {
        super.onDestroy();
        Log.d(TAG, "Service destroyed");
        isMonitoring = false;
        if (handler != null) {
            handler.removeCallbacks(scanRunnable);
        }
    }

    @Nullable
    @Override
    public IBinder onBind(Intent intent) {
        return null;
    }

    /**
     * Check if monitoring is currently enabled in preferences
     */
    public static boolean isMonitoringEnabled(Context context) {
        SharedPreferences prefs = context.getSharedPreferences(PREF_NAME, Context.MODE_PRIVATE);
        return prefs.getBoolean(PREF_MONITORING_ENABLED, false);
    }

    /**
     * Set monitoring enabled state in preferences
     */
    public static void setMonitoringEnabled(Context context, boolean enabled) {
        SharedPreferences prefs = context.getSharedPreferences(PREF_NAME, Context.MODE_PRIVATE);
        prefs.edit().putBoolean(PREF_MONITORING_ENABLED, enabled).apply();
    }
}
