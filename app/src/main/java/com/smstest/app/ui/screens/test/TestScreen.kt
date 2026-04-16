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
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import com.google.accompanist.permissions.ExperimentalPermissionsApi
import com.google.accompanist.permissions.rememberMultiplePermissionsState
import com.smstest.app.core.model.*
import com.smstest.app.core.sms.SmsManagerWrapper
import com.smstest.app.ui.screens.home.VerboseSendReportCard
import kotlinx.coroutines.launch
import java.util.UUID

/** Map any message-type string (from nav route or enum name) to the real [MessageType]. */
private fun resolveMessageType(typeStr: String): MessageType = when (typeStr.uppercase()) {
    "SMS", "SMS_TEXT" -> MessageType.SMS_TEXT
    "BINARY", "SMS_BINARY" -> MessageType.SMS_BINARY
    "FLASH", "SMS_FLASH" -> MessageType.SMS_FLASH
    "SILENT", "SMS_SILENT" -> MessageType.SMS_SILENT
    "MMS", "MMS_TEXT" -> MessageType.MMS_TEXT
    "MMS_IMAGE" -> MessageType.MMS_IMAGE
    "MMS_VIDEO" -> MessageType.MMS_VIDEO
    "MMS_AUDIO" -> MessageType.MMS_AUDIO
    "MMS_VCARD" -> MessageType.MMS_VCARD
    "MMS_MIXED" -> MessageType.MMS_MIXED
    "RCS", "RCS_TEXT" -> MessageType.RCS_TEXT
    "RCS_FILE_TRANSFER" -> MessageType.RCS_FILE_TRANSFER
    "RCS_GROUP_CHAT" -> MessageType.RCS_GROUP_CHAT
    else -> {
        com.smstest.app.core.Logger.w("TestScreen", "Unknown message type: $typeStr, defaulting to SMS_TEXT")
        MessageType.SMS_TEXT
    }
}

private val SMS_TYPES = setOf(
    MessageType.SMS_TEXT, MessageType.SMS_BINARY,
    MessageType.SMS_FLASH, MessageType.SMS_SILENT
)

@OptIn(ExperimentalMaterial3Api::class, ExperimentalPermissionsApi::class)
@Composable
fun TestScreen(
    messageType: String,
    onNavigateBack: () -> Unit
) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val snackbarHostState = remember { SnackbarHostState() }
    val smsManagerWrapper = remember { SmsManagerWrapper(context) }

    val messageTypeEnum = remember(messageType) { resolveMessageType(messageType) }
    val isSmsBased = messageTypeEnum in SMS_TYPES

    var phoneNumber by remember { mutableStateOf("") }
    var messageBody by remember { mutableStateOf("") }
    var selectedEncoding by remember { mutableStateOf(SmsEncoding.AUTO) }
    var selectedClass by remember { mutableStateOf(MessageClass.NONE) }
    var selectedPriority by remember { mutableStateOf(Priority.NORMAL) }
    var deliveryReport by remember { mutableStateOf(false) }
    var readReport by remember { mutableStateOf(false) }
    var repeatCount by remember { mutableStateOf("1") }
    var binaryPort by remember { mutableStateOf("") }
    var showAdvancedOptions by remember { mutableStateOf(false) }
    var testRunning by remember { mutableStateOf(false) }

    val lastSendReport by smsManagerWrapper.lastSendReport.collectAsState()

    // Consume any pending scenario prefill
    LaunchedEffect(Unit) {
        ScenarioPrefill.consume()?.let { (type, body) ->
            messageBody = body
            selectedEncoding = SmsEncoding.AUTO
        }
    }

    val permissionsState = rememberMultiplePermissionsState(
        permissions = listOf(
            Manifest.permission.SEND_SMS,
            Manifest.permission.READ_SMS,
            Manifest.permission.RECEIVE_SMS,
            Manifest.permission.READ_PHONE_STATE
        )
    )

    Scaffold(
        snackbarHost = { SnackbarHost(snackbarHostState) },
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

            // Non-SMS notice
            if (!isSmsBased) {
                item {
                    Card(
                        modifier = Modifier.fillMaxWidth(),
                        colors = CardDefaults.cardColors(
                            containerColor = MaterialTheme.colorScheme.tertiaryContainer
                        )
                    ) {
                        Row(
                            modifier = Modifier.padding(16.dp),
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Icon(Icons.Filled.Info, contentDescription = null)
                            Spacer(Modifier.width(8.dp))
                            Text(
                                "MMS/RCS sending is not yet implemented. " +
                                    "Only SMS types (Text, Flash, Silent, Binary) are supported.",
                                style = MaterialTheme.typography.bodySmall
                            )
                        }
                    }
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

                Text(
                    text = "${messageBody.length} characters",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.padding(start = 16.dp, top = 4.dp)
                )
            }

            // Binary port field (shown only for binary SMS)
            if (messageTypeEnum == MessageType.SMS_BINARY) {
                item {
                    OutlinedTextField(
                        value = binaryPort,
                        onValueChange = { binaryPort = it },
                        label = { Text("Destination Port") },
                        placeholder = { Text("e.g. 5000") },
                        leadingIcon = { Icon(Icons.Filled.DataObject, contentDescription = null) },
                        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                        modifier = Modifier.fillMaxWidth()
                    )
                }
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
                            scope.launch {
                                // Validate binary port before entering the try block so return@launch
                                // is valid and the finally still resets testRunning.
                                if (messageTypeEnum == MessageType.SMS_BINARY &&
                                    binaryPort.trim().isNotEmpty() &&
                                    binaryPort.trim().toIntOrNull() == null
                                ) {
                                    snackbarHostState.showSnackbar("Invalid port number — must be a valid integer")
                                    return@launch
                                }
                                testRunning = true
                                try {
                                    val port = if (messageTypeEnum == MessageType.SMS_BINARY) {
                                        binaryPort.trim().toIntOrNull()
                                    } else null

                                    val message = Message(
                                        id = UUID.randomUUID().toString(),
                                        type = messageTypeEnum,
                                        destination = phoneNumber.trim(),
                                        body = messageBody,
                                        encoding = selectedEncoding,
                                        messageClass = selectedClass,
                                        priority = selectedPriority,
                                        deliveryReport = deliveryReport,
                                        readReport = readReport,
                                        port = port
                                    )

                                    val result = smsManagerWrapper.sendSms(message)
                                    snackbarHostState.showSnackbar(
                                        result.fold(
                                            onSuccess = { "Message queued for delivery" },
                                            onFailure = { "Send failed: ${it.message}" }
                                        )
                                    )
                                } finally {
                                    testRunning = false
                                }
                            }
                        },
                        modifier = Modifier.weight(1f),
                        enabled = phoneNumber.isNotEmpty() && messageBody.isNotEmpty() &&
                            permissionsState.allPermissionsGranted && !testRunning && isSmsBased
                    ) {
                        Icon(Icons.Filled.Send, contentDescription = null)
                        Spacer(Modifier.width(8.dp))
                        Text(if (testRunning) "Sending…" else "Send Test")
                    }

                    OutlinedButton(
                        onClick = {
                            phoneNumber = ""
                            messageBody = ""
                            binaryPort = ""
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

            // Send report card
            lastSendReport?.let { report ->
                item {
                    VerboseSendReportCard(report = report)
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
                "SMS Test needs SMS permissions to send and receive test messages.",
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
        "SMS", "SMS_TEXT" -> listOf(
            MessageTemplate("Simple", "Hello, this is a test message."),
            MessageTemplate("GSM 7-bit", "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"),
            MessageTemplate("Unicode", "Hello 世界 🌍 Привет مرحبا"),
            MessageTemplate("Long Message", "A".repeat(200)),
            MessageTemplate("Special Chars", "Test: @£\$¥èéùìòÇ\\nØø\\rÅå")
        )
        "CONCATENATION", "CONCAT" -> listOf(
            MessageTemplate("160+ chars", "A".repeat(170)),
            MessageTemplate("Multi-part", "B".repeat(500))
        )
        "ENCODING" -> listOf(
            MessageTemplate("GSM Basic", "ABC123"),
            MessageTemplate("GSM Extended", "{}[]\\^€|~"),
            MessageTemplate("UCS-2", "你好世界")
        )
        "FLASH", "SMS_FLASH" -> listOf(
            MessageTemplate("Flash Test", "FLASH TEST ZERO"),
            MessageTemplate("Alert", "URGENT: This is a flash message")
        )
        "SILENT", "SMS_SILENT" -> listOf(
            MessageTemplate("Silent Ping", "Silent ping"),
            MessageTemplate("Network Check", "Network presence check")
        )
        "BINARY", "SMS_BINARY" -> listOf(
            MessageTemplate("Hex payload", "DEADBEEF"),
            MessageTemplate("Short data", "0102030405")
        )
        else -> listOf(
            MessageTemplate("Basic Test", "Test message for $type")
        )
    }
}

fun getRfcForType(type: String): List<String> {
    return when (type.uppercase()) {
        "SMS", "SMS_TEXT" -> listOf(
            "GSM 03.40 - SMS Point-to-Point",
            "GSM 03.38 - Character Set",
            "3GPP TS 23.040 - Technical Realization"
        )
        "FLASH", "SMS_FLASH" -> listOf(
            "GSM 03.40 Section 9.2.3.9",
            "3GPP TS 23.040 - TP-DCS Class 0"
        )
        "SILENT", "SMS_SILENT" -> listOf(
            "GSM 03.40 Section 9.2.3.9 - Type 0 SMS",
            "3GPP TS 23.040 - PID=0x40"
        )
        "BINARY", "SMS_BINARY" -> listOf(
            "GSM 03.40 - Port Addressing",
            "3GPP TS 23.040 - UDH (User Data Header)"
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
        else -> listOf("Industry standard compliant")
    }
}

