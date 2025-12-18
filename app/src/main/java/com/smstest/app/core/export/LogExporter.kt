package com.smstest.app.core.export

import android.content.Context
import android.content.Intent
import android.net.Uri
import android.util.Log
import androidx.core.content.FileProvider
import com.smstest.app.core.root.RootAccessManager
import com.smstest.app.core.root.RootActivity
import com.smstest.app.core.root.RootActivityType
import com.smstest.app.core.model.TestResult
import com.smstest.app.core.model.TestStatus
import java.io.File
import java.text.SimpleDateFormat
import java.util.*

/**
 * Log and Results Export Utility
 * 
 * Provides functionality to export activity logs and test results
 * to shareable files (CSV, JSON, or plain text).
 */
object LogExporter {
    
    private const val TAG = "LogExporter"
    
    /**
     * Export activity logs to a text file and share
     * @param context Android context
     * @param logs Activity logs from RootAccessManager
     * @return True if export was successful
     */
    fun exportActivityLogs(context: Context, logs: List<RootActivity>? = null): Boolean {
        return try {
            val activityLogs = logs ?: RootAccessManager.activityLog.value
            
            if (activityLogs.isEmpty()) {
                Log.w(TAG, "No activity logs to export")
                return false
            }
            
            val dateFormat = SimpleDateFormat("yyyy-MM-dd_HH-mm-ss", Locale.US)
            val timestamp = dateFormat.format(Date())
            val fileName = "zerosms_logs_$timestamp.txt"
            
            val logFormat = SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS", Locale.US)
            
            val content = buildString {
                appendLine("========================================")
                appendLine("ZeroSMS Activity Log Export")
                appendLine("Generated: ${logFormat.format(Date())}")
                appendLine("Total Entries: ${activityLogs.size}")
                appendLine("========================================")
                appendLine()
                
                activityLogs.forEach { activity ->
                    val time = logFormat.format(Date(activity.timestamp))
                    val typeIcon = when (activity.type) {
                        RootActivityType.SUCCESS -> "[✓]"
                        RootActivityType.ERROR -> "[✗]"
                        RootActivityType.WARNING -> "[!]"
                        RootActivityType.INFO -> "[i]"
                        RootActivityType.DEBUG -> "[D]"
                    }
                    appendLine("$time $typeIcon ${activity.message}")
                }
                
                appendLine()
                appendLine("========================================")
                appendLine("End of Log Export")
                appendLine("========================================")
            }
            
            shareTextFile(context, fileName, content, "text/plain")
            Log.i(TAG, "Activity logs exported successfully: $fileName")
            true
        } catch (e: Exception) {
            Log.e(TAG, "Failed to export activity logs", e)
            false
        }
    }
    
    /**
     * Export test results to a CSV file and share
     * @param context Android context
     * @param results Test results to export
     * @return True if export was successful
     */
    fun exportTestResults(context: Context, results: List<TestResult>): Boolean {
        return try {
            if (results.isEmpty()) {
                Log.w(TAG, "No test results to export")
                return false
            }
            
            val dateFormat = SimpleDateFormat("yyyy-MM-dd_HH-mm-ss", Locale.US)
            val timestamp = dateFormat.format(Date())
            val fileName = "zerosms_results_$timestamp.csv"
            
            val csvContent = buildString {
                // CSV Header
                appendLine("Scenario ID,Message ID,Status,Delivery Status,Timestamp,Duration (ms),Message Size,Parts,Errors,RFC Violations")
                
                // CSV Data
                results.forEach { result ->
                    val errors = result.errors.joinToString("; ").replace(",", ";").replace("\n", " ")
                    val violations = result.rfcViolations.joinToString("; ").replace(",", ";").replace("\n", " ")
                    
                    appendLine(listOf(
                        result.scenarioId,
                        result.messageId,
                        result.status.name,
                        result.deliveryStatus.name,
                        result.timestamp,
                        result.sendDuration.toString(),
                        result.messageSize.toString(),
                        result.messageParts.toString(),
                        "\"$errors\"",
                        "\"$violations\""
                    ).joinToString(","))
                }
            }
            
            shareTextFile(context, fileName, csvContent, "text/csv")
            Log.i(TAG, "Test results exported successfully: $fileName")
            true
        } catch (e: Exception) {
            Log.e(TAG, "Failed to export test results", e)
            false
        }
    }
    
    /**
     * Export test results summary as plain text
     * @param context Android context
     * @param results Test results to summarize
     * @return True if export was successful
     */
    fun exportTestSummary(context: Context, results: List<TestResult>): Boolean {
        return try {
            val dateFormat = SimpleDateFormat("yyyy-MM-dd_HH-mm-ss", Locale.US)
            val timestamp = dateFormat.format(Date())
            val fileName = "zerosms_summary_$timestamp.txt"
            
            val passed = results.count { it.status == TestStatus.PASSED }
            val failed = results.count { it.status == TestStatus.FAILED }
            val running = results.count { it.status == TestStatus.RUNNING }
            val pending = results.count { it.status == TestStatus.PENDING }
            
            val content = buildString {
                appendLine("========================================")
                appendLine("ZeroSMS Test Results Summary")
                appendLine("Generated: ${SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.US).format(Date())}")
                appendLine("========================================")
                appendLine()
                appendLine("SUMMARY")
                appendLine("-------")
                appendLine("Total Tests: ${results.size}")
                appendLine("Passed: $passed")
                appendLine("Failed: $failed")
                appendLine("Running: $running")
                appendLine("Pending: $pending")
                appendLine("Pass Rate: ${if (results.isNotEmpty()) "%.1f%%".format(passed * 100.0 / results.size) else "N/A"}")
                appendLine()
                
                if (failed > 0) {
                    appendLine("FAILED TESTS")
                    appendLine("------------")
                    results.filter { it.status == TestStatus.FAILED }.forEach { result ->
                        appendLine("• ${result.scenarioId}")
                        result.errors.forEach { error ->
                            appendLine("  Error: $error")
                        }
                        result.rfcViolations.forEach { violation ->
                            appendLine("  RFC Violation: $violation")
                        }
                        appendLine()
                    }
                }
                
                appendLine("========================================")
                appendLine("End of Summary")
                appendLine("========================================")
            }
            
            shareTextFile(context, fileName, content, "text/plain")
            Log.i(TAG, "Test summary exported successfully: $fileName")
            true
        } catch (e: Exception) {
            Log.e(TAG, "Failed to export test summary", e)
            false
        }
    }
    
    /**
     * Helper function to write file and launch share intent
     */
    private fun shareTextFile(context: Context, fileName: String, content: String, mimeType: String) {
        // Write to app's cache directory
        val cacheDir = File(context.cacheDir, "exports")
        if (!cacheDir.exists()) {
            cacheDir.mkdirs()
        }
        
        val file = File(cacheDir, fileName)
        file.writeText(content)
        
        // Get URI via FileProvider
        val uri: Uri = FileProvider.getUriForFile(
            context,
            "${context.packageName}.fileprovider",
            file
        )
        
        // Create share intent
        val shareIntent = Intent(Intent.ACTION_SEND).apply {
            type = mimeType
            putExtra(Intent.EXTRA_STREAM, uri)
            putExtra(Intent.EXTRA_SUBJECT, "ZeroSMS Export: $fileName")
            addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
        }
        
        // Launch chooser
        context.startActivity(Intent.createChooser(shareIntent, "Export to...").apply {
            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        })
    }
}
