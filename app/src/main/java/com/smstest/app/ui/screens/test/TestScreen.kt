package com.smstest.app.ui.screens.test

import android.Manifest
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import com.google.accompanist.permissions.ExperimentalPermissionsApi
import com.google.accompanist.permissions.rememberMultiplePermissionsState
import com.smstest.app.core.model.*

@OptIn(ExperimentalMaterial3Api::class, ExperimentalPermissionsApi::class)
@Composable
fun TestScreen(
    messageType: String,
    onNavigateBack: () -> Unit
) {
    var phoneNumber by remember { mutableStateOf("") }
    var messageBody by remember { mutableStateOf("") }
    var selectedEncoding by remember { mutableStateOf(SmsEncoding.AUTO) }
    var selectedClass by remember { mutableStateOf(MessageClass.NONE) }
    var selectedPriority by remember { mutableStateOf(Priority.NORMAL) }
    var deliveryReport by remember { mutableStateOf(false) }
    var readReport by remember { mutableStateOf(false) }
    var repeatCount by remember { mutableStateOf("1") }
    var showAdvancedOptions by remember { mutableStateOf(false) }
    var testRunning by remember { mutableStateOf(false) }
    
    // Request permissions
    val permissionsState = rememberMultiplePermissionsState(
        permissions = listOf(
            Manifest.permission.SEND_SMS,
            Manifest.permission.READ_SMS,
            Manifest.permission.RECEIVE_SMS,
            Manifest.permission.READ_PHONE_STATE
        )
    )
    
    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("$messageType Testing") },
                navigationIcon = {
                    IconButton(onClick = onNavigateBack) {
                        Icon(Icons.Filled.ArrowBack, contentDescription = "Back")
                    }
                },
                actions = {
                    IconButton(onClick = { showAdvancedOptions = !showAdvancedOptions }) {
                        Icon(
                            if (showAdvancedOptions) Icons.Filled.ExpandLess else Icons.Filled.ExpandMore,
                            contentDescription = "Advanced Options"
                        )
                    }
                }
            )
        }
    ) { paddingValues ->
        LazyColumn(
            modifier = Modifier
                .fillMaxSize()
                .padding(paddingValues)
                .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp)
        ) {
            // Permissions check
            if (!permissionsState.allPermissionsGranted) {
                item {
                    PermissionCard(
                        onRequestPermissions = { permissionsState.launchMultiplePermissionRequest() }
                    )
                }
            }
            
            // Phone Number Input
            item {
                OutlinedTextField(
                    value = phoneNumber,
                    onValueChange = { phoneNumber = it },
                    label = { Text("Phone Number") },
                    placeholder = { Text("+1234567890") },
                    leadingIcon = { Icon(Icons.Filled.Phone, contentDescription = null) },
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Phone),
                    modifier = Modifier.fillMaxWidth()
                )
            }
            
            // Message Body
            item {
                OutlinedTextField(
                    value = messageBody,
                    onValueChange = { messageBody = it },
                    label = { Text("Message Content") },
                    placeholder = { Text("Enter test message...") },
                    leadingIcon = { Icon(Icons.Filled.Message, contentDescription = null) },
                    minLines = 3,
                    maxLines = 5,
                    modifier = Modifier.fillMaxWidth()
                )
                
                // Character counter
                Text(
                    text = "${messageBody.length} characters",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.padding(start = 16.dp, top = 4.dp)
                )
            }
            
            // Quick Test Templates
            item {
                TestTemplatesSection(
                    messageType = messageType,
                    onTemplateSelected = { template ->
                        messageBody = template
                    }
                )
            }
            
            // Advanced Options
            if (showAdvancedOptions) {
                item {
                    AdvancedOptionsCard(
                        selectedEncoding = selectedEncoding,
                        onEncodingChange = { selectedEncoding = it },
                        selectedClass = selectedClass,
                        onClassChange = { selectedClass = it },
                        selectedPriority = selectedPriority,
                        onPriorityChange = { selectedPriority = it },
                        deliveryReport = deliveryReport,
                        onDeliveryReportChange = { deliveryReport = it },
                        readReport = readReport,
                        onReadReportChange = { readReport = it },
                        repeatCount = repeatCount,
                        onRepeatCountChange = { repeatCount = it }
                    )
                }
            }
            
            // RFC Compliance Info
            item {
                RfcComplianceCard(messageType = messageType)
            }
            
            // Action Buttons
            item {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    Button(
                        onClick = {
                            testRunning = true
                            // Execute test based on message type and configuration
                        },
                        modifier = Modifier.weight(1f),
                        enabled = phoneNumber.isNotEmpty() && messageBody.isNotEmpty() && 
                                 permissionsState.allPermissionsGranted && !testRunning
                    ) {
                        Icon(Icons.Filled.Send, contentDescription = null)
                        Spacer(Modifier.width(8.dp))
                        Text(if (testRunning) "Running..." else "Send Test")
                    }
                    
                    OutlinedButton(
                        onClick = {
                            phoneNumber = ""
                            messageBody = ""
                        },
                        modifier = Modifier.weight(1f)
                    ) {
                        Icon(Icons.Filled.Clear, contentDescription = null)
                        Spacer(Modifier.width(8.dp))
                        Text("Clear")
                    }
                }
            }
            
            // Test Progress
            if (testRunning) {
                item {
                    TestProgressCard()
                }
            }
        }
    }
}

@Composable
fun PermissionCard(
    onRequestPermissions: () -> Unit
) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.errorContainer
        )
    ) {
        Column(
            modifier = Modifier.padding(16.dp)
        ) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Icon(
                    Icons.Filled.Warning,
                    contentDescription = null,
                    tint = MaterialTheme.colorScheme.error
                )
                Spacer(Modifier.width(8.dp))
                Text(
                    "Permissions Required",
                    style = MaterialTheme.typography.titleMedium,
                    color = MaterialTheme.colorScheme.error
                )
            }
            
            Spacer(Modifier.height(8.dp))
            
            Text(
                "ZeroSMS needs SMS permissions to send and receive test messages.",
                style = MaterialTheme.typography.bodySmall
            )
            
            Spacer(Modifier.height(12.dp))
            
            Button(
                onClick = onRequestPermissions,
                modifier = Modifier.fillMaxWidth()
            ) {
                Text("Grant Permissions")
            }
        }
    }
}

@Composable
fun TestTemplatesSection(
    messageType: String,
    onTemplateSelected: (String) -> Unit
) {
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(modifier = Modifier.padding(16.dp)) {
            Text(
                "Quick Templates",
                style = MaterialTheme.typography.titleSmall
            )
            
            Spacer(Modifier.height(8.dp))
            
            val templates = getTemplatesForType(messageType)
            
            templates.forEach { template ->
                AssistChip(
                    onClick = { onTemplateSelected(template.content) },
                    label = { Text(template.name) },
                    modifier = Modifier.padding(vertical = 4.dp)
                )
            }
        }
    }
}

@Composable
fun AdvancedOptionsCard(
    selectedEncoding: SmsEncoding,
    onEncodingChange: (SmsEncoding) -> Unit,
    selectedClass: MessageClass,
    onClassChange: (MessageClass) -> Unit,
    selectedPriority: Priority,
    onPriorityChange: (Priority) -> Unit,
    deliveryReport: Boolean,
    onDeliveryReportChange: (Boolean) -> Unit,
    readReport: Boolean,
    onReadReportChange: (Boolean) -> Unit,
    repeatCount: String,
    onRepeatCountChange: (String) -> Unit
) {
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(modifier = Modifier.padding(16.dp)) {
            Text(
                "Advanced Options",
                style = MaterialTheme.typography.titleMedium
            )
            
            Spacer(Modifier.height(16.dp))
            
            // Encoding
            Text("Encoding (GSM 03.38)", style = MaterialTheme.typography.bodySmall)
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                SmsEncoding.values().forEach { encoding ->
                    FilterChip(
                        selected = selectedEncoding == encoding,
                        onClick = { onEncodingChange(encoding) },
                        label = { Text(encoding.name) }
                    )
                }
            }
            
            Spacer(Modifier.height(12.dp))
            
            // Message Class
            Text("Message Class", style = MaterialTheme.typography.bodySmall)
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                MessageClass.values().take(4).forEach { msgClass ->
                    FilterChip(
                        selected = selectedClass == msgClass,
                        onClick = { onClassChange(msgClass) },
                        label = { Text(msgClass.name) }
                    )
                }
            }
            
            Spacer(Modifier.height(12.dp))
            
            // Priority
            Text("Priority", style = MaterialTheme.typography.bodySmall)
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Priority.values().forEach { priority ->
                    FilterChip(
                        selected = selectedPriority == priority,
                        onClick = { onPriorityChange(priority) },
                        label = { Text(priority.name) }
                    )
                }
            }
            
            Spacer(Modifier.height(16.dp))
            
            // Reports
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text("Delivery Report")
                Switch(
                    checked = deliveryReport,
                    onCheckedChange = onDeliveryReportChange
                )
            }
            
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text("Read Report")
                Switch(
                    checked = readReport,
                    onCheckedChange = onReadReportChange
                )
            }
            
            Spacer(Modifier.height(12.dp))
            
            // Repeat Count
            OutlinedTextField(
                value = repeatCount,
                onValueChange = onRepeatCountChange,
                label = { Text("Repeat Count") },
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                modifier = Modifier.fillMaxWidth()
            )
        }
    }
}

@Composable
fun RfcComplianceCard(messageType: String) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.secondaryContainer
        )
    ) {
        Column(modifier = Modifier.padding(16.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Icon(Icons.Filled.VerifiedUser, contentDescription = null)
                Spacer(Modifier.width(8.dp))
                Text(
                    "RFC Compliance",
                    style = MaterialTheme.typography.titleSmall
                )
            }
            
            Spacer(Modifier.height(8.dp))
            
            val rfcs = getRfcForType(messageType)
            rfcs.forEach { rfc ->
                Text(
                    "• $rfc",
                    style = MaterialTheme.typography.bodySmall
                )
            }
        }
    }
}

@Composable
fun TestProgressCard() {
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(
            modifier = Modifier.padding(16.dp),
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            CircularProgressIndicator()
            Spacer(Modifier.height(16.dp))
            Text("Sending test message...")
            Text(
                "Monitoring delivery status...",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
    }
}

data class MessageTemplate(
    val name: String,
    val content: String
)

fun getTemplatesForType(type: String): List<MessageTemplate> {
    return when (type.uppercase()) {
        "SMS" -> listOf(
            MessageTemplate("Simple", "Hello, this is a test message."),
            MessageTemplate("GSM 7-bit", "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"),
            MessageTemplate("Unicode", "Hello 世界 🌍 Привет مرحبا"),
            MessageTemplate("Long Message", "A".repeat(200)),
            MessageTemplate("Special Chars", "Test: @£\$¥èéùìòÇ\\nØø\\rÅå")
        )
        "CONCATENATION" -> listOf(
            MessageTemplate("160+ chars", "A".repeat(170)),
            MessageTemplate("Multi-part", "B".repeat(500))
        )
        "ENCODING" -> listOf(
            MessageTemplate("GSM Basic", "ABC123"),
            MessageTemplate("GSM Extended", "{}[]\\^€|~"),
            MessageTemplate("UCS-2", "你好世界")
        )
        else -> listOf(
            MessageTemplate("Basic Test", "Test message for $type")
        )
    }
}

fun getRfcForType(type: String): List<String> {
    return when (type.uppercase()) {
        "SMS" -> listOf(
            "GSM 03.40 - SMS Point-to-Point",
            "GSM 03.38 - Character Set",
            "3GPP TS 23.040 - Technical Realization"
        )
        "MMS" -> listOf(
            "OMA MMS Encapsulation Protocol",
            "WAP-209-MMSEncapsulation",
            "RFC 2046 - MIME Types"
        )
        "RCS" -> listOf(
            "GSMA RCS Universal Profile 2.4",
            "RFC 4975 - MSRP Protocol",
            "RFC 6120 - XMPP Core"
        )
        else -> listOf(
            "Industry standard compliant"
        )
    }
}
