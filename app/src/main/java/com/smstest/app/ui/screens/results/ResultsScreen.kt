package com.smstest.app.ui.screens.results

import android.widget.Toast
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ArrowBack
import androidx.compose.material.icons.filled.Download
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.Error
import androidx.compose.material.icons.filled.Schedule
import androidx.compose.material.icons.filled.Cancel
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.smstest.app.core.export.LogExporter
import com.smstest.app.core.tracking.MessageTracker
import com.smstest.app.core.tracking.TrackedMessage
import com.smstest.app.ui.theme.*
import java.text.SimpleDateFormat
import java.util.*

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ResultsScreen(
    onNavigateBack: () -> Unit
) {
    val context = LocalContext.current
    val messagesMap by MessageTracker.messages.collectAsState()
    val messages = remember(messagesMap) { messagesMap.values.sortedByDescending { it.createdAt } }
    var selectedFilter by remember { mutableStateOf("ALL") }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Test Results") },
                navigationIcon = {
                    IconButton(onClick = onNavigateBack) {
                        Icon(Icons.Filled.ArrowBack, contentDescription = "Back")
                    }
                },
                actions = {
                    IconButton(onClick = {
                        if (messages.isEmpty()) {
                            Toast.makeText(context, "No results to export", Toast.LENGTH_SHORT).show()
                        } else {
                            LogExporter.exportTrackedMessages(context, messages)
                        }
                    }) {
                        Icon(Icons.Filled.Download, contentDescription = "Export")
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
            TrackedMessageSummary(messages)

            Spacer(Modifier.height(16.dp))

            // Filter Chips
            Row(
                horizontalArrangement = Arrangement.spacedBy(8.dp),
                modifier = Modifier.padding(bottom = 16.dp)
            ) {
                listOf("ALL", "SENT", "DELIVERED", "FAILED", "PREPARING").forEach { filter ->
                    FilterChip(
                        selected = selectedFilter == filter,
                        onClick = { selectedFilter = filter },
                        label = { Text(filter) }
                    )
                }
            }

            // Results List
            if (messages.isEmpty()) {
                Box(
                    modifier = Modifier.fillMaxSize(),
                    contentAlignment = Alignment.Center
                ) {
                    Text(
                        "No messages sent yet.\nUse Test Scenarios or the Send button to get started.",
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
            } else {
                LazyColumn(
                    verticalArrangement = Arrangement.spacedBy(12.dp)
                ) {
                    val filtered = messages.filter { msg ->
                        selectedFilter == "ALL" || msg.status == selectedFilter
                    }
                    items(filtered, key = { it.id }) { msg ->
                        TrackedMessageCard(msg)
                    }
                }
            }
        }
    }
}

@Composable
private fun TrackedMessageSummary(messages: List<TrackedMessage>) {
    val sent = messages.count { it.status in listOf("SENT", "DELIVERED") }
    val failed = messages.count { it.status == "FAILED" }
    val pending = messages.count { it.status == "PREPARING" }

    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.spacedBy(8.dp)
    ) {
        SummaryCard(title = "Sent", count = sent, color = SuccessGreen, modifier = Modifier.weight(1f))
        SummaryCard(title = "Failed", count = failed, color = ErrorRed, modifier = Modifier.weight(1f))
        SummaryCard(title = "Pending", count = pending, color = WarningOrange, modifier = Modifier.weight(1f))
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
        colors = CardDefaults.cardColors(containerColor = color.copy(alpha = 0.1f))
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
private fun TrackedMessageCard(msg: TrackedMessage) {
    var expanded by remember { mutableStateOf(false) }
    val tsFormat = remember { SimpleDateFormat("MMM dd HH:mm:ss", Locale.getDefault()) }

    val statusColor = when (msg.status) {
        "DELIVERED" -> SuccessGreen
        "SENT" -> SuccessGreen
        "FAILED" -> ErrorRed
        else -> WarningOrange
    }
    val statusIcon = when (msg.status) {
        "DELIVERED", "SENT" -> Icons.Filled.CheckCircle
        "FAILED" -> Icons.Filled.Error
        "PREPARING" -> Icons.Filled.Schedule
        else -> Icons.Filled.Cancel
    }

    Card(
        onClick = { expanded = !expanded },
        modifier = Modifier.fillMaxWidth()
    ) {
        Column(modifier = Modifier.padding(16.dp)) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically
            ) {
                Icon(
                    imageVector = statusIcon,
                    contentDescription = null,
                    tint = statusColor
                )
                Spacer(Modifier.width(12.dp))
                Column(modifier = Modifier.weight(1f)) {
                    Text(
                        text = msg.destination,
                        style = MaterialTheme.typography.titleMedium,
                        fontWeight = FontWeight.Bold
                    )
                    Text(
                        text = "${msg.type} • ${tsFormat.format(Date(msg.createdAt))}",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
                Badge(containerColor = statusColor) {
                    Text(msg.status)
                }
            }

            if (expanded) {
                HorizontalDivider(modifier = Modifier.padding(vertical = 8.dp))
                Text("ID: ${msg.id.take(8)}…", style = MaterialTheme.typography.bodySmall)
                Text("Encoding: ${msg.encoding}", style = MaterialTheme.typography.bodySmall)
                Text("Class: ${msg.messageClass}", style = MaterialTheme.typography.bodySmall)
                if (msg.body.isNotBlank()) {
                    Text("Body: ${msg.body.take(80)}${if (msg.body.length > 80) "…" else ""}",
                        style = MaterialTheme.typography.bodySmall)
                }
                if (msg.statusHistory.isNotEmpty()) {
                    Spacer(Modifier.height(4.dp))
                    Text("History", style = MaterialTheme.typography.labelMedium, fontWeight = FontWeight.SemiBold)
                    msg.statusHistory.takeLast(5).forEach { update ->
                        val t = tsFormat.format(Date(update.timestamp))
                        val detail = if (update.details.isNotBlank()) " — ${update.details}" else ""
                        Text("• $t ${update.status}$detail", style = MaterialTheme.typography.bodySmall)
                    }
                }
            }
        }
    }
}
