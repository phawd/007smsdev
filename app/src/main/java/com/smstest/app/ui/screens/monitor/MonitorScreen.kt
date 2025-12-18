package com.smstest.app.ui.screens.monitor

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Info
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.smstest.app.core.database.IncomingSms
import com.smstest.app.core.receiver.SmsReceiver
import com.smstest.app.core.model.MessageType
import kotlinx.coroutines.delay
import java.text.SimpleDateFormat
import java.util.*

/**
 * SMS Monitor Screen
 * 
 * Displays incoming SMS including Class 0 (Flash) and Type 0 (Silent)
 * for operator monitoring and analysis.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun MonitorScreen(
    onNavigateBack: () -> Unit
) {
    var messages by remember { mutableStateOf<List<IncomingSms>>(emptyList()) }
    var filterType by remember { mutableStateOf<MessageType?>(null) }
    var showDetails by remember { mutableStateOf<IncomingSms?>(null) }
    var autoRefresh by remember { mutableStateOf(true) }
    
    val database = SmsReceiver.getDatabase()
    
    // Auto-refresh messages
    LaunchedEffect(autoRefresh) {
        while (autoRefresh) {
            messages = when (filterType) {
                MessageType.SMS_FLASH -> database.getFlashMessages()
                MessageType.SMS_SILENT -> database.getSilentMessages()
                null -> database.getAllMessages()
                else -> database.getAllMessages().filter { it.messageType == filterType }
            }
            delay(1000)  // Refresh every second
        }
    }
    
    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("SMS Monitor") },
                actions = {
                    // Auto-refresh toggle
                    IconButton(onClick = { autoRefresh = !autoRefresh }) {
                        Icon(
                            Icons.Filled.Refresh,
                            contentDescription = "Auto-refresh",
                            tint = if (autoRefresh) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurface
                        )
                    }
                    
                    // Clear all
                    IconButton(onClick = { 
                        database.clearAll()
                        messages = emptyList()
                    }) {
                        Icon(Icons.Filled.Delete, contentDescription = "Clear All")
                    }
                }
            )
        }
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
        ) {
            // Filter chips
            FilterChips(
                currentFilter = filterType,
                onFilterChange = { filterType = it }
            )
            
            // Message count
            SummaryBar(
                totalCount = database.getMessageCount(),
                flashCount = database.getFlashMessages().size,
                silentCount = database.getSilentMessages().size
            )
            
            // Message list
            if (messages.isEmpty()) {
                Box(
                    modifier = Modifier.fillMaxSize(),
                    contentAlignment = Alignment.Center
                ) {
                    Column(horizontalAlignment = Alignment.CenterHorizontally) {
                        Text(
                            "No messages received",
                            style = MaterialTheme.typography.bodyLarge,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                        Spacer(modifier = Modifier.height(8.dp))
                        Text(
                            "Monitoring for Class 0 and Type 0 SMS",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                }
            } else {
                LazyColumn(
                    modifier = Modifier.fillMaxSize(),
                    contentPadding = PaddingValues(16.dp),
                    verticalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    items(messages) { message ->
                        MessageCard(
                            message = message,
                            onClick = { showDetails = message }
                        )
                    }
                }
            }
        }
    }
    
    // Detail dialog
    showDetails?.let { message ->
        MessageDetailDialog(
            message = message,
            onDismiss = { showDetails = null }
        )
    }
}

@Composable
fun FilterChips(
    currentFilter: MessageType?,
    onFilterChange: (MessageType?) -> Unit
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(16.dp),
        horizontalArrangement = Arrangement.spacedBy(8.dp)
    ) {
        FilterChip(
            selected = currentFilter == null,
            onClick = { onFilterChange(null) },
            label = { Text("All") }
        )
        FilterChip(
            selected = currentFilter == MessageType.SMS_FLASH,
            onClick = { onFilterChange(MessageType.SMS_FLASH) },
            label = { Text("Flash (Class 0)") }
        )
        FilterChip(
            selected = currentFilter == MessageType.SMS_SILENT,
            onClick = { onFilterChange(MessageType.SMS_SILENT) },
            label = { Text("Silent (Type 0)") }
        )
    }
}

@Composable
fun SummaryBar(
    totalCount: Int,
    flashCount: Int,
    silentCount: Int
) {
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 16.dp),
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.primaryContainer
        )
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(16.dp),
            horizontalArrangement = Arrangement.SpaceEvenly
        ) {
            StatItem("Total", totalCount)
            StatItem("Flash", flashCount)
            StatItem("Silent", silentCount)
        }
    }
}

@Composable
fun StatItem(label: String, count: Int) {
    Column(horizontalAlignment = Alignment.CenterHorizontally) {
        Text(
            text = count.toString(),
            style = MaterialTheme.typography.headlineMedium,
            fontWeight = FontWeight.Bold,
            color = MaterialTheme.colorScheme.onPrimaryContainer
        )
        Text(
            text = label,
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onPrimaryContainer
        )
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun MessageCard(
    message: IncomingSms,
    onClick: () -> Unit
) {
    val dateFormat = SimpleDateFormat("MM/dd HH:mm:ss", Locale.getDefault())
    
    Card(
        onClick = onClick,
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(
            containerColor = when {
                message.isFlash -> MaterialTheme.colorScheme.errorContainer
                message.isSilent -> MaterialTheme.colorScheme.tertiaryContainer
                else -> MaterialTheme.colorScheme.surfaceVariant
            }
        )
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(16.dp)
        ) {
            // Header row
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                // Type badge
                AssistChip(
                    onClick = {},
                    label = { 
                        Text(
                            when {
                                message.isFlash -> "FLASH"
                                message.isSilent -> "SILENT"
                                else -> "NORMAL"
                            }
                        )
                    },
                    colors = AssistChipDefaults.assistChipColors(
                        containerColor = when {
                            message.isFlash -> MaterialTheme.colorScheme.error
                            message.isSilent -> MaterialTheme.colorScheme.tertiary
                            else -> MaterialTheme.colorScheme.secondary
                        },
                        labelColor = when {
                            message.isFlash -> MaterialTheme.colorScheme.onError
                            message.isSilent -> MaterialTheme.colorScheme.onTertiary
                            else -> MaterialTheme.colorScheme.onSecondary
                        }
                    )
                )
                
                // Timestamp
                Text(
                    text = dateFormat.format(Date(message.timestamp)),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
            
            Spacer(modifier = Modifier.height(8.dp))
            
            // Sender
            Text(
                text = "From: ${message.sender}",
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.Bold
            )
            
            Spacer(modifier = Modifier.height(4.dp))
            
            // Message body preview
            Text(
                text = message.body.take(100) + if (message.body.length > 100) "..." else "",
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurface
            )
            
            Spacer(modifier = Modifier.height(8.dp))
            
            // Technical details
            Row(
                horizontalArrangement = Arrangement.spacedBy(16.dp)
            ) {
                Text(
                    text = "Class: ${message.messageClass}",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                Text(
                    text = "PID: 0x${message.protocolId.toString(16)}",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                Text(
                    text = message.encoding.name,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        }
    }
}

@Composable
fun MessageDetailDialog(
    message: IncomingSms,
    onDismiss: () -> Unit
) {
    val dateFormat = SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS", Locale.getDefault())
    
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Message Details") },
        text = {
            LazyColumn(
                verticalArrangement = Arrangement.spacedBy(12.dp)
            ) {
                item {
                    DetailItem("Type", when {
                        message.isFlash -> "Flash SMS (Class 0)"
                        message.isSilent -> "Silent SMS (Type 0)"
                        else -> "Normal SMS"
                    })
                }
                item { DetailItem("Sender", message.sender) }
                item { DetailItem("Timestamp", dateFormat.format(Date(message.timestamp))) }
                item { DetailItem("Message Class", message.messageClass.toString()) }
                item { DetailItem("Protocol ID", "0x${message.protocolId.toString(16)} (${message.protocolId})") }
                item { DetailItem("Encoding", message.encoding.toString()) }
                item { 
                    Column {
                        Text(
                            "Message Body:",
                            style = MaterialTheme.typography.labelMedium,
                            fontWeight = FontWeight.Bold
                        )
                        Spacer(modifier = Modifier.height(4.dp))
                        Text(
                            message.body,
                            style = MaterialTheme.typography.bodyMedium
                        )
                    }
                }
                
                message.rawPdu?.let { pdu ->
                    item {
                        Column {
                            Text(
                                "Raw PDU:",
                                style = MaterialTheme.typography.labelMedium,
                                fontWeight = FontWeight.Bold
                            )
                            Spacer(modifier = Modifier.height(4.dp))
                            Text(
                                pdu,
                                style = MaterialTheme.typography.bodySmall,
                                fontFamily = FontFamily.Monospace,
                                modifier = Modifier
                                    .background(MaterialTheme.colorScheme.surfaceVariant)
                                    .padding(8.dp)
                            )
                        }
                    }
                }
            }
        },
        confirmButton = {
            TextButton(onClick = onDismiss) {
                Text("Close")
            }
        }
    )
}

@Composable
fun DetailItem(label: String, value: String) {
    Column {
        Text(
            text = label,
            style = MaterialTheme.typography.labelMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
        Text(
            text = value,
            style = MaterialTheme.typography.bodyMedium,
            fontWeight = FontWeight.Medium
        )
    }
}
