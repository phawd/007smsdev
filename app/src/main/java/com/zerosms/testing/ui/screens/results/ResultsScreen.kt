package com.zerosms.testing.ui.screens.results

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.zerosms.testing.core.model.*
import com.zerosms.testing.ui.theme.*
import java.text.SimpleDateFormat
import java.util.*

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ResultsScreen(
    onNavigateBack: () -> Unit
) {
    // Mock data for demonstration
    val testResults = remember { generateMockResults() }
    var selectedFilter by remember { mutableStateOf("ALL") }
    
    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Test Results") },
                navigationIcon = {
                    IconButton(onClick = onNavigateBack) {
                        Icon(Icons.Default.ArrowBack, contentDescription = "Back")
                    }
                },
                actions = {
                    IconButton(onClick = { /* Export results */ }) {
                        Icon(Icons.Default.Download, contentDescription = "Export")
                    }
                }
            )
        }
    ) { paddingValues ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(paddingValues)
                .padding(16.dp)
        ) {
            // Summary Cards
            TestSummaryCards(testResults)
            
            Spacer(Modifier.height(16.dp))
            
            // Filter Chips
            Row(
                horizontalArrangement = Arrangement.spacedBy(8.dp),
                modifier = Modifier.padding(bottom = 16.dp)
            ) {
                listOf("ALL", "PASSED", "FAILED", "RUNNING").forEach { filter ->
                    FilterChip(
                        selected = selectedFilter == filter,
                        onClick = { selectedFilter = filter },
                        label = { Text(filter) }
                    )
                }
            }
            
            // Results List
            LazyColumn(
                verticalArrangement = Arrangement.spacedBy(12.dp)
            ) {
                val filteredResults = testResults.filter {
                    selectedFilter == "ALL" || it.status.name == selectedFilter
                }
                
                items(filteredResults) { result ->
                    TestResultCard(result = result)
                }
            }
        }
    }
}

@Composable
fun TestSummaryCards(results: List<TestResult>) {
    val passed = results.count { it.status == TestStatus.PASSED }
    val failed = results.count { it.status == TestStatus.FAILED }
    val running = results.count { it.status == TestStatus.RUNNING }
    
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.spacedBy(8.dp)
    ) {
        SummaryCard(
            title = "Passed",
            count = passed,
            color = SuccessGreen,
            modifier = Modifier.weight(1f)
        )
        SummaryCard(
            title = "Failed",
            count = failed,
            color = ErrorRed,
            modifier = Modifier.weight(1f)
        )
        SummaryCard(
            title = "Running",
            count = running,
            color = WarningOrange,
            modifier = Modifier.weight(1f)
        )
    }
}

@Composable
fun SummaryCard(
    title: String,
    count: Int,
    color: androidx.compose.ui.graphics.Color,
    modifier: Modifier = Modifier
) {
    Card(
        modifier = modifier,
        colors = CardDefaults.cardColors(
            containerColor = color.copy(alpha = 0.1f)
        )
    ) {
        Column(
            modifier = Modifier.padding(16.dp),
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            Text(
                text = count.toString(),
                style = MaterialTheme.typography.headlineLarge,
                fontWeight = FontWeight.Bold,
                color = color
            )
            Text(
                text = title,
                style = MaterialTheme.typography.bodySmall,
                color = color
            )
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun TestResultCard(result: TestResult) {
    var expanded by remember { mutableStateOf(false) }
    
    Card(
        onClick = { expanded = !expanded },
        modifier = Modifier.fillMaxWidth()
    ) {
        Column(modifier = Modifier.padding(16.dp)) {
            // Header
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically
            ) {
                Icon(
                    imageVector = when (result.status) {
                        TestStatus.PASSED -> Icons.Default.CheckCircle
                        TestStatus.FAILED -> Icons.Default.Error
                        TestStatus.RUNNING -> Icons.Default.Schedule
                        TestStatus.TIMEOUT -> Icons.Default.AccessTime
                        TestStatus.CANCELLED -> Icons.Default.Cancel
                    },
                    contentDescription = null,
                    tint = when (result.status) {
                        TestStatus.PASSED -> SuccessGreen
                        TestStatus.FAILED -> ErrorRed
                        TestStatus.RUNNING -> WarningOrange
                        TestStatus.TIMEOUT -> WarningOrange
                        TestStatus.CANCELLED -> MaterialTheme.colorScheme.onSurfaceVariant
                    }
                )
                
                Spacer(Modifier.width(12.dp))
                
                Column(modifier = Modifier.weight(1f)) {
                    Text(
                        text = result.scenarioId,
                        style = MaterialTheme.typography.titleMedium,
                        fontWeight = FontWeight.Bold
                    )
                    Text(
                        text = SimpleDateFormat("MMM dd, yyyy HH:mm:ss", Locale.getDefault())
                            .format(result.startTime),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
                
                Badge {
                    Text(result.status.name)
                }
            }
            
            // Delivery Status
            Spacer(Modifier.height(8.dp))
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween
            ) {
                Text(
                    text = "Delivery: ${result.deliveryStatus}",
                    style = MaterialTheme.typography.bodySmall
                )
                result.metrics?.let {
                    Text(
                        text = "${it.sendDuration}ms",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.primary
                    )
                }
            }
            
            // Expanded Details
            if (expanded) {
                Divider(modifier = Modifier.padding(vertical = 12.dp))
                
                // Metrics
                result.metrics?.let { metrics ->
                    Text("Performance Metrics", style = MaterialTheme.typography.titleSmall)
                    Spacer(Modifier.height(8.dp))
                    
                    MetricRow("Send Duration", "${metrics.sendDuration}ms")
                    metrics.deliveryDuration?.let {
                        MetricRow("Delivery Duration", "${it}ms")
                    }
                    MetricRow("Message Size", "${metrics.messageSize} bytes")
                    MetricRow("Parts Sent", "${metrics.partsSent}")
                    MetricRow("Parts Received", "${metrics.partsReceived}")
                }
                
                // Errors
                if (result.errors.isNotEmpty()) {
                    Spacer(Modifier.height(12.dp))
                    Text("Errors", style = MaterialTheme.typography.titleSmall)
                    result.errors.forEach { error ->
                        Text(
                            text = "• $error",
                            style = MaterialTheme.typography.bodySmall,
                            color = ErrorRed
                        )
                    }
                }
                
                // RFC Violations
                if (result.rfcViolations.isNotEmpty()) {
                    Spacer(Modifier.height(12.dp))
                    Text("RFC Violations", style = MaterialTheme.typography.titleSmall)
                    result.rfcViolations.forEach { violation ->
                        Text(
                            text = "• $violation",
                            style = MaterialTheme.typography.bodySmall,
                            color = WarningOrange
                        )
                    }
                }
            }
        }
    }
}

@Composable
fun MetricRow(label: String, value: String) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 4.dp),
        horizontalArrangement = Arrangement.SpaceBetween
    ) {
        Text(
            text = label,
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
        Text(
            text = value,
            style = MaterialTheme.typography.bodySmall,
            fontWeight = FontWeight.Bold
        )
    }
}

fun generateMockResults(): List<TestResult> {
    return listOf(
        TestResult(
            scenarioId = "SMS_TEXT_BASIC",
            messageId = "msg_001",
            startTime = Date(System.currentTimeMillis() - 3600000),
            endTime = Date(System.currentTimeMillis() - 3599000),
            status = TestStatus.PASSED,
            deliveryStatus = DeliveryStatus.DELIVERED,
            metrics = TestMetrics(
                sendDuration = 245,
                deliveryDuration = 1200,
                messageSize = 160,
                partsSent = 1,
                partsReceived = 1
            )
        ),
        TestResult(
            scenarioId = "SMS_CONCATENATION_LONG",
            messageId = "msg_002",
            startTime = Date(System.currentTimeMillis() - 7200000),
            endTime = Date(System.currentTimeMillis() - 7199000),
            status = TestStatus.PASSED,
            deliveryStatus = DeliveryStatus.DELIVERED,
            metrics = TestMetrics(
                sendDuration = 890,
                deliveryDuration = 3400,
                messageSize = 500,
                partsSent = 4,
                partsReceived = 4
            )
        ),
        TestResult(
            scenarioId = "MMS_IMAGE_TRANSFER",
            messageId = "msg_003",
            startTime = Date(System.currentTimeMillis() - 10800000),
            status = TestStatus.FAILED,
            deliveryStatus = DeliveryStatus.FAILED,
            errors = listOf(
                "Attachment size exceeds carrier limit",
                "Connection timeout to MMSC"
            ),
            metrics = TestMetrics(
                sendDuration = 5600,
                deliveryDuration = null,
                messageSize = 524288,
                partsSent = 1,
                partsReceived = 0
            )
        ),
        TestResult(
            scenarioId = "RCS_FILE_TRANSFER",
            messageId = "msg_004",
            startTime = Date(System.currentTimeMillis() - 1800000),
            status = TestStatus.RUNNING,
            deliveryStatus = DeliveryStatus.SENT
        )
    )
}
