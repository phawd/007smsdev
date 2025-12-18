package com.smstest.app.ui.screens.home

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Abc
import androidx.compose.material.icons.filled.BarChart
import androidx.compose.material.icons.filled.Cancel
import androidx.compose.material.icons.filled.Chat
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.ChevronRight
import androidx.compose.material.icons.filled.DataObject
import androidx.compose.material.icons.filled.DoneAll
import androidx.compose.material.icons.filled.FlashOn
import androidx.compose.material.icons.filled.Message
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material.icons.filled.Speed
import androidx.compose.material.icons.filled.ViewStream
import androidx.compose.material.icons.filled.Visibility
import androidx.compose.material.icons.filled.VisibilityOff
import androidx.compose.material3.AssistChip
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import com.smstest.app.BuildConfig
import com.smstest.app.core.device.DeviceInfo
import com.smstest.app.core.device.DeviceInfoManager
import com.smstest.app.core.device.ModemChipset
import com.smstest.app.core.device.ModemInfo
import com.smstest.app.core.model.Message
import com.smstest.app.core.model.MessageClass
import com.smstest.app.core.model.MessageType
import com.smstest.app.core.device.SmsStrategy
import com.smstest.app.core.root.RootAccessManager
import com.smstest.app.core.settings.SettingsRepository
import com.smstest.app.core.sms.SmsManagerWrapper
import com.smstest.app.ui.theme.MMSGreen
import com.smstest.app.ui.theme.RCSPurple
import com.smstest.app.ui.theme.SMSBlue
import java.util.UUID
import kotlinx.coroutines.flow.collectLatest
import kotlinx.coroutines.launch

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun HomeScreen(
    onNavigateToTest: (String) -> Unit,
    onNavigateToResults: () -> Unit,
    onNavigateToSettings: () -> Unit,
    onNavigateToMonitor: () -> Unit = {}
) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val snackbarHostState = remember { SnackbarHostState() }
    val smsManagerWrapper = remember { SmsManagerWrapper(context) }

    var flashNumber by remember { mutableStateOf("") }
    var flashMessage by remember { mutableStateOf("FLASH TEST ZERO") }
    var silentMessage by remember { mutableStateOf("TYPE0 TEST ZERO") }
    var sendingFlash by remember { mutableStateOf(false) }
    var sendingSilent by remember { mutableStateOf(false) }
    var rootAvailable by remember { mutableStateOf<Boolean?>(null) }
    var atReady by remember { mutableStateOf(false) }

    val deviceInfo by DeviceInfoManager.deviceInfo.collectAsState()
    val modemInfo by DeviceInfoManager.modemInfo.collectAsState()
    val detectionProgress by DeviceInfoManager.detectionProgress.collectAsState()
    val detectionRunning by DeviceInfoManager.isDetecting.collectAsState()
    val testCategories = remember { getTestCategories() }

    LaunchedEffect(Unit) {
        DeviceInfoManager.initialize(context)
        val root = RootAccessManager.isRootAvailable()
        rootAvailable = root
        if (root) {
            atReady = smsManagerWrapper.initializeAtCommands()
        }
    }

    LaunchedEffect(Unit) {
        SettingsRepository.flashDestinationFlow(context).collectLatest { stored ->
            if (stored.isNotBlank()) {
                flashNumber = stored
            }
        }
    }

    val capabilities = remember(deviceInfo, modemInfo, rootAvailable, atReady) {
        buildCapabilityList(
            deviceInfo = deviceInfo,
            modemInfo = modemInfo,
            rootAvailable = rootAvailable,
            atReady = atReady,
            strategy = DeviceInfoManager.getRecommendedSmsStrategy()
        )
    }

    Scaffold(
        snackbarHost = { SnackbarHost(snackbarHostState) },
        topBar = {
            TopAppBar(
                title = {
                    val commit = remember {
                        runCatching { BuildConfig::class.java.getField("GIT_COMMIT").get(null) as? String }
                            .getOrNull() ?: "n/a"
                    }
                    Text("SMS Test v${BuildConfig.VERSION_NAME} (${BuildConfig.VERSION_CODE}) • $commit")
                },
                actions = {
                    IconButton(onClick = onNavigateToSettings) {
                        Icon(Icons.Filled.Settings, contentDescription = "Settings")
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
            item {
                Column {
                    Text(
                        text = "Comprehensive SMS/MMS/RCS Testing",
                        style = MaterialTheme.typography.headlineMedium,
                        fontWeight = FontWeight.Bold
                    )
                    Text(
                        text = "RFC-compliant tooling for flash, silent, MMS, and RCS scenarios",
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
            }

            item {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(12.dp)
                ) {
                    Button(
                        onClick = onNavigateToResults,
                        modifier = Modifier.weight(1f)
                    ) {
                        Icon(Icons.Filled.BarChart, contentDescription = null)
                        Spacer(Modifier.width(8.dp))
                        Text("Results")
                    }
                    Button(
                        onClick = onNavigateToMonitor,
                        modifier = Modifier.weight(1f),
                        colors = ButtonDefaults.buttonColors(
                            containerColor = MaterialTheme.colorScheme.tertiary
                        )
                    ) {
                        Icon(Icons.Filled.Visibility, contentDescription = null)
                        Spacer(Modifier.width(8.dp))
                        Text("SMS Monitor")
                    }
                }
            }

            item {
                DeviceCapabilitySection(
                    deviceInfo = deviceInfo,
                    modemInfo = modemInfo,
                    detectionRunning = detectionRunning,
                    detectionProgress = detectionProgress,
                    rootAvailable = rootAvailable,
                    atReady = atReady,
                    onRunDetection = {
                        scope.launch { DeviceInfoManager.refresh(context) }
                    },
                    onInitAt = {
                        scope.launch {
                            if (rootAvailable != false) {
                                atReady = smsManagerWrapper.initializeAtCommands()
                                snackbarHostState.showSnackbar(
                                    if (atReady) "AT commands ready" else "AT initialization failed"
                                )
                            } else {
                                snackbarHostState.showSnackbar("Root access required for AT")
                            }
                        }
                    }
                )
            }

            item {
                FlashAndSilentCard(
                    flashNumber = flashNumber,
                    onNumberChanged = { flashNumber = it },
                    flashMessage = flashMessage,
                    onFlashMessageChanged = { flashMessage = it },
                    silentMessage = silentMessage,
                    onSilentMessageChanged = { silentMessage = it },
                    sendingFlash = sendingFlash,
                    sendingSilent = sendingSilent,
                    rootAvailable = rootAvailable,
                    atReady = atReady,
                    onSendFlash = {
                        scope.launch {
                            if (flashNumber.isBlank()) {
                                snackbarHostState.showSnackbar("Enter destination number")
                                return@launch
                            }
                            sendingFlash = true
                            val result = smsManagerWrapper.sendSms(
                                Message(
                                    id = UUID.randomUUID().toString(),
                                    type = MessageType.SMS_FLASH,
                                    destination = flashNumber.trim(),
                                    body = flashMessage,
                                    messageClass = MessageClass.CLASS_0
                                )
                            )
                            sendingFlash = false
                            snackbarHostState.showSnackbar(
                                result.fold(
                                    onSuccess = { "Flash SMS queued" },
                                    onFailure = { "Flash SMS failed: ${it.message}" }
                                )
                            )
                        }
                    },
                    onSendSilent = {
                        scope.launch {
                            if (flashNumber.isBlank()) {
                                snackbarHostState.showSnackbar("Enter destination number")
                                return@launch
                            }
                            sendingSilent = true
                            val result = smsManagerWrapper.sendSms(
                                Message(
                                    id = UUID.randomUUID().toString(),
                                    type = MessageType.SMS_SILENT,
                                    destination = flashNumber.trim(),
                                    body = silentMessage
                                )
                            )
                            sendingSilent = false
                            snackbarHostState.showSnackbar(
                                result.fold(
                                    onSuccess = { "Type 0 SMS queued" },
                                    onFailure = { "Type 0 SMS failed: ${it.message}" }
                                )
                            )
                        }
                    }
                )
            }

            item {
                Column {
                    Text(
                        text = "Sending Capabilities",
                        style = MaterialTheme.typography.titleLarge,
                        fontWeight = FontWeight.Bold
                    )
                    Spacer(Modifier.height(8.dp))
                    CapabilityChips(capabilities = capabilities)
                }
            }

            item {
                Text(
                    text = "Test Categories",
                    style = MaterialTheme.typography.titleLarge,
                    fontWeight = FontWeight.Bold
                )
            }

            items(testCategories) { category ->
                TestCategoryCard(
                    category = category,
                    onClick = { onNavigateToTest(category.type) }
                )
            }
        }
    }
}

@Composable
private fun DeviceCapabilitySection(
    deviceInfo: DeviceInfo?,
    modemInfo: ModemInfo?,
    detectionRunning: Boolean,
    detectionProgress: List<String>,
    rootAvailable: Boolean?,
    atReady: Boolean,
    onRunDetection: () -> Unit,
    onInitAt: () -> Unit
) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant)
    ) {
        Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
            Text("Device Capability Discovery", style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Bold)
            Text(
                text = deviceInfo?.let { "${it.manufacturer} ${it.model}" } ?: "Unknown device",
                style = MaterialTheme.typography.bodyMedium
            )
            Text(
                text = modemInfo?.let { "${it.chipset.displayName} • ${it.atCommandMethod}" } ?: "Modem not detected",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )

            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                AssistChip(
                    onClick = {},
                    label = { Text(if (rootAvailable == true) "Root available" else "Root required") },
                    leadingIcon = {
                        Icon(
                            imageVector = if (rootAvailable == true) Icons.Filled.CheckCircle else Icons.Filled.Cancel,
                            contentDescription = null,
                            tint = if (rootAvailable == true) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.error
                        )
                    }
                )
                AssistChip(
                    onClick = {},
                    label = { Text(if (atReady) "AT ready" else "Init AT") },
                    leadingIcon = {
                        Icon(
                            imageVector = if (atReady) Icons.Filled.CheckCircle else Icons.Filled.Cancel,
                            contentDescription = null,
                            tint = if (atReady) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.error
                        )
                    }
                )
            }

            Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                Button(onClick = onRunDetection, enabled = !detectionRunning) {
                    Icon(Icons.Filled.Refresh, contentDescription = null)
                    Spacer(Modifier.width(8.dp))
                    Text(if (detectionRunning) "Scanning…" else "Run Discovery")
                }
                OutlinedButton(onClick = onInitAt) {
                    Icon(Icons.Filled.FlashOn, contentDescription = null)
                    Spacer(Modifier.width(8.dp))
                    Text("Initialize AT")
                }
            }

            val recentLogs = detectionProgress.takeLast(3)
            if (recentLogs.isNotEmpty()) {
                Column {
                    Text("Recent activity", style = MaterialTheme.typography.labelMedium)
                    recentLogs.forEach { log ->
                        Text(log, style = MaterialTheme.typography.bodySmall)
                    }
                }
            }
        }
    }
}

@Composable
private fun FlashAndSilentCard(
    flashNumber: String,
    onNumberChanged: (String) -> Unit,
    flashMessage: String,
    onFlashMessageChanged: (String) -> Unit,
    silentMessage: String,
    onSilentMessageChanged: (String) -> Unit,
    sendingFlash: Boolean,
    sendingSilent: Boolean,
    rootAvailable: Boolean?,
    atReady: Boolean,
    onSendFlash: () -> Unit,
    onSendSilent: () -> Unit
) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(16.dp)
    ) {
        Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
            Text("Flash / Type 0 Test Harness", style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Bold)
            OutlinedTextField(
                value = flashNumber,
                onValueChange = onNumberChanged,
                label = { Text("Destination (E.164)") },
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Phone),
                modifier = Modifier.fillMaxWidth()
            )
            OutlinedTextField(
                value = flashMessage,
                onValueChange = onFlashMessageChanged,
                label = { Text("Flash payload") },
                modifier = Modifier.fillMaxWidth()
            )
            OutlinedTextField(
                value = silentMessage,
                onValueChange = onSilentMessageChanged,
                label = { Text("Type 0 payload") },
                modifier = Modifier.fillMaxWidth()
            )

            Row(horizontalArrangement = Arrangement.spacedBy(12.dp), modifier = Modifier.fillMaxWidth()) {
                Button(
                    onClick = onSendFlash,
                    enabled = !sendingFlash && flashNumber.isNotBlank(),
                    modifier = Modifier.weight(1f)
                ) {
                    if (sendingFlash) {
                        CircularProgressIndicator(modifier = Modifier.size(18.dp), strokeWidth = 2.dp)
                        Spacer(Modifier.width(8.dp))
                        Text("Sending…")
                    } else {
                        Icon(Icons.Filled.FlashOn, contentDescription = null)
                        Spacer(Modifier.width(8.dp))
                        Text("Send Flash")
                    }
                }
                Button(
                    onClick = onSendSilent,
                    enabled = !sendingSilent && flashNumber.isNotBlank(),
                    modifier = Modifier.weight(1f)
                ) {
                    if (sendingSilent) {
                        CircularProgressIndicator(modifier = Modifier.size(18.dp), strokeWidth = 2.dp)
                        Spacer(Modifier.width(8.dp))
                        Text("Sending…")
                    } else {
                        Icon(Icons.Filled.VisibilityOff, contentDescription = null)
                        Spacer(Modifier.width(8.dp))
                        Text("Send Type 0")
                    }
                }
            }

            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                AssistChip(
                    onClick = {},
                    label = { Text(if (rootAvailable == true) "Root OK" else "Root missing") },
                    leadingIcon = {
                        Icon(
                            imageVector = if (rootAvailable == true) Icons.Filled.CheckCircle else Icons.Filled.Cancel,
                            contentDescription = null,
                            tint = if (rootAvailable == true) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.error
                        )
                    }
                )
                AssistChip(
                    onClick = {},
                    label = { Text(if (atReady) "AT ready" else "AT required") },
                    leadingIcon = {
                        Icon(
                            imageVector = if (atReady) Icons.Filled.CheckCircle else Icons.Filled.Cancel,
                            contentDescription = null,
                            tint = if (atReady) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.error
                        )
                    }
                )
            }
        }
    }
}

@Composable
private fun CapabilityChips(capabilities: List<Capability>, modifier: Modifier = Modifier) {
    Column(modifier = modifier.fillMaxWidth(), verticalArrangement = Arrangement.spacedBy(8.dp)) {
        capabilities.forEach { cap ->
            AssistChip(
                onClick = {},
                enabled = cap.available,
                label = {
                    Column {
                        Text(cap.label, fontWeight = FontWeight.SemiBold)
                        Text(
                            cap.detail,
                            style = MaterialTheme.typography.labelSmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                },
                leadingIcon = {
                    Icon(
                        imageVector = if (cap.available) Icons.Filled.CheckCircle else Icons.Filled.Cancel,
                        contentDescription = null,
                        tint = if (cap.available) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.error
                    )
                }
            )
        }
    }
}

private fun buildCapabilityList(
    deviceInfo: DeviceInfo?,
    modemInfo: ModemInfo?,
    rootAvailable: Boolean?,
    atReady: Boolean,
    strategy: SmsStrategy
): List<Capability> {
    val summaryDevice = deviceInfo?.let { "${it.manufacturer} ${it.model}" } ?: "Run discovery"
    val summaryChipset = modemInfo?.chipset?.displayName ?: ModemChipset.UNKNOWN.displayName
    val radio = modemInfo?.radioType?.displayName ?: "Radio unknown"
    val strategyLabel = strategy.name.replace('_', ' ').lowercase().replaceFirstChar { it.titlecase() }

    val capabilities = mutableListOf(
        Capability("DEVICE", "Device", deviceInfo != null, summaryDevice),
        Capability("CHIPSET", "Chipset", modemInfo != null, "$summaryChipset • $radio"),
        Capability("ROOT", "Root Access", rootAvailable == true, if (rootAvailable == true) "su detected" else "su not found"),
        Capability("AT", "AT Channel", atReady, if (atReady) "Modem ready" else "Initialize AT for PDUs"),
        Capability("FLASH", "Flash SMS", atReady || rootAvailable == true, if (atReady) "TP-DCS 0x10" else "Fallback via SmsManager"),
        Capability("TYPE0", "Silent SMS", atReady, if (atReady) "PID 0x40 supported" else "Requires AT init"),
        Capability("STRATEGY", "Strategy", true, strategyLabel)
    )

    if (modemInfo?.supportsDirectModemAccess == true) {
        capabilities.add(
            Capability(
                "DIRECT_MODEM",
                "Direct Modem Access",
                true,
                modemInfo.modemDevicePaths.joinToString()
            )
        )
    }

    return capabilities
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun TestCategoryCard(
    category: TestCategory,
    onClick: () -> Unit
) {
    Card(
        onClick = onClick,
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(containerColor = category.color.copy(alpha = 0.12f))
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(16.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Icon(
                imageVector = category.icon,
                contentDescription = null,
                tint = category.color,
                modifier = Modifier.size(48.dp)
            )
            Spacer(Modifier.width(16.dp))
            Column(modifier = Modifier.weight(1f)) {
                Text(category.title, style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Bold)
                Text(category.description, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                Text("${category.testCount} tests", style = MaterialTheme.typography.labelSmall, color = category.color)
            }
            Icon(Icons.Filled.ChevronRight, contentDescription = null)
        }
    }
}

data class TestCategory(
    val type: String,
    val title: String,
    val description: String,
    val icon: ImageVector,
    val color: Color,
    val testCount: Int
)

data class Capability(
    val key: String,
    val label: String,
    val available: Boolean,
    val detail: String
)

private fun getTestCategories(): List<TestCategory> = listOf(
    TestCategory(
        type = "SMS",
        title = "SMS Testing",
        description = "GSM 03.40 compliant cases",
        icon = Icons.Filled.Message,
        color = SMSBlue,
        testCount = 15
    ),
    TestCategory(
        type = "MMS",
        title = "MMS Testing",
        description = "OMA MMS encapsulation",
        icon = Icons.Filled.Message,
        color = MMSGreen,
        testCount = 12
    ),
    TestCategory(
        type = "RCS",
        title = "RCS Testing",
        description = "GSMA UP 2.4",
        icon = Icons.Filled.Chat,
        color = RCSPurple,
        testCount = 10
    ),
    TestCategory(
        type = "BINARY",
        title = "Binary SMS",
        description = "Port addressing + 8-bit",
        icon = Icons.Filled.DataObject,
        color = SMSBlue,
        testCount = 8
    ),
    TestCategory(
        type = "FLASH",
        title = "Flash SMS",
        description = "Class 0 immediacy",
        icon = Icons.Filled.FlashOn,
        color = SMSBlue,
        testCount = 5
    ),
    TestCategory(
        type = "SILENT",
        title = "Silent SMS",
        description = "Type 0 probing",
        icon = Icons.Filled.VisibilityOff,
        color = SMSBlue,
        testCount = 6
    ),
    TestCategory(
        type = "CONCAT",
        title = "Concatenation",
        description = "Multi-part scenarios",
        icon = Icons.Filled.ViewStream,
        color = SMSBlue,
        testCount = 7
    ),
    TestCategory(
        type = "ENCODING",
        title = "Encoding",
        description = "GSM 7-bit/UCS-2",
        icon = Icons.Filled.Abc,
        color = SMSBlue,
        testCount = 9
    ),
    TestCategory(
        type = "DELIVERY",
        title = "Delivery Reports",
        description = "Status + DLR tests",
        icon = Icons.Filled.DoneAll,
        color = MMSGreen,
        testCount = 6
    ),
    TestCategory(
        type = "STRESS",
        title = "Stress Testing",
        description = "High volume",
        icon = Icons.Filled.Speed,
        color = RCSPurple,
        testCount = 8
    )
)
