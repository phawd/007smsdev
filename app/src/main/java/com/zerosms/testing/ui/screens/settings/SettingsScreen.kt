package com.zerosms.testing.ui.screens.settings

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.collectLatest
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import com.zerosms.testing.core.at.AtCapabilityScanResult
import com.zerosms.testing.core.at.AtCommandManager
import com.zerosms.testing.core.device.DeviceInfoManager
import com.zerosms.testing.core.device.SmsStrategy
import com.zerosms.testing.core.qualcomm.QualcommDiagManager
import com.zerosms.testing.core.qualcomm.QualcommDiagProfile
import com.zerosms.testing.core.settings.SettingsRepository

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SettingsScreen(onNavigateBack: () -> Unit) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val e164Regex = remember { Regex("^\\+?[1-9]\\d{6,15}$") }

    // State
    var autoDeliveryReport by remember { mutableStateOf(true) }
    var autoReadReport by remember { mutableStateOf(false) }
    var defaultEncoding by remember { mutableStateOf("AUTO") }
    var logLevel by remember { mutableStateOf("INFO") }
    var flashNumberInput by remember { mutableStateOf("") }
    var flashNumberSaved by remember { mutableStateOf("") }
    var flashNumberError by remember { mutableStateOf<String?>(null) }
    var currentMmscUrl by remember { mutableStateOf("") }
    var currentProxy by remember { mutableStateOf("") }
    var currentPort by remember { mutableStateOf("80") }

    // Load persisted settings
    LaunchedEffect(Unit) {
        SettingsRepository.flashDestinationFlow(context).collectLatest { stored ->
            flashNumberSaved = stored
            if (flashNumberInput.isBlank()) flashNumberInput = stored
        }
    }
    LaunchedEffect(Unit) { SettingsRepository.autoDeliveryFlow(context).collectLatest { autoDeliveryReport = it } }
    LaunchedEffect(Unit) { SettingsRepository.autoReadFlow(context).collectLatest { autoReadReport = it } }
    LaunchedEffect(Unit) { SettingsRepository.defaultEncodingFlow(context).collectLatest { defaultEncoding = it } }
    LaunchedEffect(Unit) { SettingsRepository.logLevelFlow(context).collectLatest { logLevel = it } }
    LaunchedEffect(Unit) { SettingsRepository.mmscUrlFlow(context).collectLatest { currentMmscUrl = it } }
    LaunchedEffect(Unit) { SettingsRepository.mmscProxyFlow(context).collectLatest { currentProxy = it } }
    LaunchedEffect(Unit) { SettingsRepository.mmscPortFlow(context).collectLatest { currentPort = it } }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Settings") },
                navigationIcon = { IconButton(onClick = onNavigateBack) { Icon(Icons.Default.ArrowBack, "Back") } }
            )
        }
    ) { paddingValues ->
        LazyColumn(
            modifier = Modifier.fillMaxSize().padding(paddingValues).padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp)
        ) {
            item { Text("Messaging Options", style = MaterialTheme.typography.titleLarge) }
            item {
                Card(modifier = Modifier.fillMaxWidth()) {
                    Column(modifier = Modifier.padding(16.dp)) {
                        SettingRow("Automatic Delivery Reports", "Request delivery confirmation", autoDeliveryReport) {
                            autoDeliveryReport = it
                            scope.launch { SettingsRepository.setAutoDelivery(context, it) }
                        }
                        Divider(modifier = Modifier.padding(vertical = 8.dp))
                        SettingRow("Automatic Read Reports", "Request read receipts", autoReadReport) {
                            autoReadReport = it
                            scope.launch { SettingsRepository.setAutoRead(context, it) }
                        }
                    }
                }
            }
            item { Text("Default Parameters", style = MaterialTheme.typography.titleLarge) }
            item {
                Card(modifier = Modifier.fillMaxWidth()) {
                    Column(modifier = Modifier.padding(16.dp)) {
                        Text("Default Encoding", style = MaterialTheme.typography.titleSmall)
                        Spacer(Modifier.height(8.dp))
                        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                            listOf("AUTO", "GSM_7BIT", "UCS2").forEach { enc ->
                                FilterChip(selected = defaultEncoding == enc, onClick = {
                                    defaultEncoding = enc
                                    scope.launch { SettingsRepository.setDefaultEncoding(context, enc) }
                                }, label = { Text(enc) })
                            }
                        }
                    }
                }
            }
            item { Text("Advanced Features", style = MaterialTheme.typography.titleLarge) }
            item { DeviceDetectionCard() }
            item { RootAccessCard() }
            item { MmscConfigCard(currentMmscUrl, currentProxy, currentPort, { currentMmscUrl = it }, { currentProxy = it }, { currentPort = it }) }
            item { Text("Flash SMS", style = MaterialTheme.typography.titleLarge) }
            item {
                Card(modifier = Modifier.fillMaxWidth()) {
                    Column(modifier = Modifier.padding(16.dp)) {
                        Text("Destination Number (E.164)", style = MaterialTheme.typography.titleSmall)
                        Spacer(Modifier.height(8.dp))
                        OutlinedTextField(
                            value = flashNumberInput,
                            onValueChange = { flashNumberInput = it.filter { ch -> ch.isDigit() || ch == '+' }; flashNumberError = null },
                            label = { Text("Flash SMS Number") },
                            placeholder = { Text("+15551234567") },
                            isError = flashNumberError != null,
                            supportingText = { Text(flashNumberError ?: if (flashNumberSaved.isNotBlank()) "Saved: $flashNumberSaved" else "Enter destination") },
                            modifier = Modifier.fillMaxWidth()
                        )
                        Spacer(Modifier.height(12.dp))
                        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                            Button(onClick = {
                                val c = flashNumberInput.trim()
                                when {
                                    c.isBlank() -> flashNumberError = "Required"
                                    !e164Regex.matches(c) -> flashNumberError = "Invalid E.164"
                                    else -> { scope.launch { SettingsRepository.setFlashDestination(context, c) }; flashNumberError = null }
                                }
                            }, enabled = flashNumberInput.isNotBlank(), modifier = Modifier.weight(1f)) {
                                Icon(Icons.Default.Save, null); Spacer(Modifier.width(8.dp)); Text("Save")
                            }
                            OutlinedButton(onClick = { flashNumberInput = flashNumberSaved; flashNumberError = null }, modifier = Modifier.weight(1f), enabled = flashNumberSaved.isNotBlank()) {
                                Icon(Icons.Default.Refresh, null); Spacer(Modifier.width(8.dp)); Text("Reset")
                            }
                        }
                    }
                }
            }
            item { Text("Testing & Debugging", style = MaterialTheme.typography.titleLarge) }
            item {
                Card(modifier = Modifier.fillMaxWidth()) {
                    Column(modifier = Modifier.padding(16.dp)) {
                        Text("Log Level", style = MaterialTheme.typography.titleSmall)
                        Spacer(Modifier.height(8.dp))
                        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                            listOf("DEBUG", "INFO", "WARN", "ERROR").forEach { lvl ->
                                FilterChip(selected = logLevel == lvl, onClick = {
                                    logLevel = lvl
                                    scope.launch { SettingsRepository.setLogLevel(context, lvl) }
                                }, label = { Text(lvl) })
                            }
                        }
                        Spacer(Modifier.height(16.dp))
                        Button(onClick = { /* TODO: Export logs */ }, modifier = Modifier.fillMaxWidth()) {
                            Icon(Icons.Default.FileDownload, null); Spacer(Modifier.width(8.dp)); Text("Export Logs")
                        }
                    }
                }
            }
            item { Text("RFC Compliance", style = MaterialTheme.typography.titleLarge) }
            item {
                Card(modifier = Modifier.fillMaxWidth(), colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.secondaryContainer)) {
                    Column(modifier = Modifier.padding(16.dp)) {
                        Text("Standards Implemented", style = MaterialTheme.typography.titleSmall)
                        Spacer(Modifier.height(8.dp))
                        listOf("GSM 03.40 - SMS P2P", "GSM 03.38 - Charset", "3GPP TS 23.040", "OMA MMS", "GSMA RCS UP 2.4").forEach { Text("• $it", style = MaterialTheme.typography.bodySmall) }
                    }
                }
            }
            item { Text("About", style = MaterialTheme.typography.titleLarge) }
            item {
                Card(modifier = Modifier.fillMaxWidth()) {
                    Column(modifier = Modifier.padding(16.dp), horizontalAlignment = Alignment.CenterHorizontally) {
                        Text("ZeroSMS Testing Suite", style = MaterialTheme.typography.titleMedium)
                        Text("Version 1.0.0", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                    }
                }
            }
        }
    }
}

@Composable
fun SettingRow(title: String, subtitle: String, checked: Boolean, onCheckedChange: (Boolean) -> Unit) {
    Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween, verticalAlignment = Alignment.CenterVertically) {
        Column(modifier = Modifier.weight(1f)) {
            Text(title, style = MaterialTheme.typography.bodyLarge)
            Text(subtitle, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
        Switch(checked = checked, onCheckedChange = onCheckedChange)
    }
}

@Composable
fun RootAccessCard() {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var rootAvailable by remember { mutableStateOf<Boolean?>(null) }
    var atReady by remember { mutableStateOf<Boolean?>(null) }
    var modemDevice by remember { mutableStateOf<String?>(null) }
    var detectedDevices by remember { mutableStateOf<List<String>>(emptyList()) }
    var selectedDevice by remember { mutableStateOf<String?>(null) }
    var diagUsbConfig by remember { mutableStateOf<String?>(null) }
    var diagStatusMessage by remember { mutableStateOf("Checking Qualcomm diagnostic USB config...") }
    var diagInProgress by remember { mutableStateOf(false) }
    val diagProfiles = remember { QualcommDiagManager.getPresetProfiles() }
    var selectedDiagProfileId by remember { mutableStateOf(diagProfiles.firstOrNull()?.id) }

    val selectedDiagProfile: QualcommDiagProfile? = remember(selectedDiagProfileId, diagProfiles) {
        diagProfiles.firstOrNull { it.id == selectedDiagProfileId }
    }

    LaunchedEffect(Unit) {
        withContext(Dispatchers.IO) {
            val root = AtCommandManager.isRootAvailable()
            val list = AtCommandManager.probeDevices()
            rootAvailable = root
            detectedDevices = list
            selectedDevice = list.firstOrNull()
            modemDevice = selectedDevice
            atReady = root && selectedDevice != null
        }
    }

    LaunchedEffect(Unit) {
        scope.launch {
            val config = withContext(Dispatchers.IO) { QualcommDiagManager.getActiveUsbConfig() }
            diagUsbConfig = config
            diagStatusMessage = config?.let { "USB config: $it" } ?: "Qualcomm USB config unavailable"
        }
    }

    Card(modifier = Modifier.fillMaxWidth(), colors = CardDefaults.cardColors(
        containerColor = when (rootAvailable) { true -> MaterialTheme.colorScheme.primaryContainer; false -> MaterialTheme.colorScheme.errorContainer; null -> MaterialTheme.colorScheme.surfaceVariant }
    )) {
        Column(modifier = Modifier.padding(16.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Icon(if (rootAvailable == true) Icons.Default.CheckCircle else Icons.Default.Warning, null)
                Text("Root Access & AT Commands", style = MaterialTheme.typography.titleMedium)
            }
            Spacer(Modifier.height(12.dp))
            StatusRow("Root Access", rootAvailable)
            StatusRow("AT Commands", atReady)
            Spacer(Modifier.height(8.dp))
            if (detectedDevices.isNotEmpty()) {
                Text("Detected modem devices:", style = MaterialTheme.typography.bodySmall)
                Spacer(Modifier.height(8.dp))
                detectedDevices.forEach { d ->
                    Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.clickable { selectedDevice = d }) {
                        RadioButton(selected = selectedDevice == d, onClick = { selectedDevice = d })
                        Text(d)
                    }
                }
            } else {
                Text("No modem devices detected", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
            modemDevice?.let { Spacer(Modifier.height(8.dp)); Text("Active: $it", style = MaterialTheme.typography.bodySmall) }
            Spacer(Modifier.height(12.dp))
            Text("AT commands enable direct modem access for Class 0/Type 0 SMS. Root required.", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            Spacer(Modifier.height(12.dp))
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp), modifier = Modifier.fillMaxWidth()) {
                Button(onClick = {
                    scope.launch {
                        val list = withContext(Dispatchers.IO) { AtCommandManager.probeDevices() }
                        detectedDevices = list
                        selectedDevice = list.firstOrNull()
                    }
                }, modifier = Modifier.weight(1f)) { Icon(Icons.Default.Refresh, null); Spacer(Modifier.width(8.dp)); Text("Rescan") }
                Button(onClick = {
                    scope.launch {
                        val dev = selectedDevice ?: return@launch
                        val ok = withContext(Dispatchers.IO) { AtCommandManager.initializeAtOnDevice(dev) }
                        atReady = ok
                        modemDevice = if (ok) dev else null
                        SettingsRepository.setAtInitialized(context, ok)
                        SettingsRepository.setLastModemDevice(context, dev)
                    }
                }, modifier = Modifier.weight(1f)) { Icon(Icons.Default.PlayArrow, null); Spacer(Modifier.width(8.dp)); Text("Initialize") }
            }
            Spacer(Modifier.height(16.dp))
            Divider()
            Spacer(Modifier.height(12.dp))
            Text("Qualcomm Diagnostic Ports", style = MaterialTheme.typography.titleSmall)
            Spacer(Modifier.height(4.dp))
            Text("Select the diag USB profile that matches your device. Inseego/NOVAtel units may require the diag_mdm option.", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            Spacer(Modifier.height(8.dp))
            diagProfiles.forEach { profile ->
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    modifier = Modifier
                        .fillMaxWidth()
                        .clickable { selectedDiagProfileId = profile.id }
                        .padding(vertical = 4.dp)
                ) {
                    RadioButton(
                        selected = selectedDiagProfileId == profile.id,
                        onClick = { selectedDiagProfileId = profile.id }
                    )
                    Column(modifier = Modifier.padding(start = 8.dp)) {
                        Text(profile.label, style = MaterialTheme.typography.bodyMedium)
                        Text(profile.description, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                    }
                }
            }
            Spacer(Modifier.height(8.dp))
            Text(diagStatusMessage, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            Text("Active USB config: ${diagUsbConfig ?: "Unknown"}", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            Spacer(Modifier.height(8.dp))
            Button(
                onClick = {
                    scope.launch {
                        diagInProgress = true
                        diagStatusMessage = "Applying Qualcomm diagnostic USB configuration..."
                        val result = withContext(Dispatchers.IO) { QualcommDiagManager.enableDiagnosticPorts(selectedDiagProfile) }
                        diagUsbConfig = result.activeConfig
                        diagStatusMessage = result.message
                        diagInProgress = false
                    }
                },
                modifier = Modifier.fillMaxWidth(),
                enabled = !diagInProgress
            ) {
                Text(if (diagInProgress) "Applying diag configuration…" else "Enable Qualcomm Diag Ports")
            }
        }
    }
}

@Composable
fun MmscConfigCard(url: String, proxy: String, port: String, onUrlChange: (String) -> Unit, onProxyChange: (String) -> Unit, onPortChange: (String) -> Unit) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(modifier = Modifier.padding(16.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Icon(Icons.Default.Cloud, null)
                Text("MMSC Configuration", style = MaterialTheme.typography.titleMedium)
            }
            Spacer(Modifier.height(12.dp))
            OutlinedTextField(value = url, onValueChange = onUrlChange, label = { Text("MMSC URL") }, placeholder = { Text("http://mmsc.example.com") }, modifier = Modifier.fillMaxWidth())
            Spacer(Modifier.height(8.dp))
            Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedTextField(value = proxy, onValueChange = onProxyChange, label = { Text("Proxy") }, modifier = Modifier.weight(1f))
                OutlinedTextField(value = port, onValueChange = onPortChange, label = { Text("Port") }, modifier = Modifier.weight(1f))
            }
            Spacer(Modifier.height(12.dp))
            Button(onClick = { scope.launch { SettingsRepository.setMmscConfig(context, url, proxy, port) } }, modifier = Modifier.fillMaxWidth()) {
                Icon(Icons.Default.Save, null); Spacer(Modifier.width(8.dp)); Text("Save Configuration")
            }
        }
    }
}

@Composable
fun StatusRow(label: String, status: Boolean?) {
    Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween, verticalAlignment = Alignment.CenterVertically) {
        Text(label, style = MaterialTheme.typography.bodyMedium)
        AssistChip(onClick = {}, label = { Text(when (status) { true -> "Available"; false -> "Unavailable"; null -> "Checking..." }) },
            colors = AssistChipDefaults.assistChipColors(
                containerColor = when (status) { true -> MaterialTheme.colorScheme.primary; false -> MaterialTheme.colorScheme.error; null -> MaterialTheme.colorScheme.surfaceVariant },
                labelColor = when (status) { true -> MaterialTheme.colorScheme.onPrimary; false -> MaterialTheme.colorScheme.onError; null -> MaterialTheme.colorScheme.onSurfaceVariant }
            ))
    }
}

@Composable
fun DeviceDetectionCard() {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    
    // Device info states
    var isDetecting by remember { mutableStateOf(false) }
    var chipsetName by remember { mutableStateOf("Not detected") }
    var radioType by remember { mutableStateOf("Unknown") }
    var atMethod by remember { mutableStateOf("Unknown") }
    var smsStrategy by remember { mutableStateOf("Unknown") }
    var modemPaths by remember { mutableStateOf<List<String>>(emptyList()) }
    var detectionLog by remember { mutableStateOf<List<String>>(emptyList()) }
    var manufacturer by remember { mutableStateOf("") }
    var model by remember { mutableStateOf("") }
    var atCapabilityResults by remember { mutableStateOf<List<AtCapabilityScanResult>>(emptyList()) }
    
    // Collect device info from DeviceInfoManager
    LaunchedEffect(Unit) {
        DeviceInfoManager.deviceInfo.collect { info ->
            info?.let {
                manufacturer = it.manufacturer
                model = it.model
            }
        }
    }
    
    LaunchedEffect(Unit) {
        DeviceInfoManager.modemInfo.collect { info ->
            info?.let {
                chipsetName = it.chipset.displayName
                radioType = it.radioType.displayName
                atMethod = it.atCommandMethod.displayName
                modemPaths = it.modemDevicePaths
                smsStrategy = DeviceInfoManager.getRecommendedSmsStrategy().displayName
            }
        }
    }
    
    LaunchedEffect(Unit) {
        DeviceInfoManager.detectionProgress.collect { progress ->
            detectionLog = progress
            isDetecting = progress.isNotEmpty() && !progress.lastOrNull().orEmpty().contains("complete")
        }
    }

    LaunchedEffect(Unit) {
        DeviceInfoManager.atCapabilityResults.collect { results ->
            atCapabilityResults = results
        }
    }
    
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.surfaceVariant
        )
    ) {
        Column(modifier = Modifier.padding(16.dp)) {
            // Header
            Row(
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                Icon(Icons.Default.PhoneAndroid, contentDescription = null)
                Text("Device Detection", style = MaterialTheme.typography.titleMedium)
            }
            
            Spacer(Modifier.height(12.dp))
            
            // Device manufacturer & model
            if (manufacturer.isNotBlank()) {
                Text("$manufacturer $model", style = MaterialTheme.typography.bodyLarge)
                Spacer(Modifier.height(8.dp))
            }
            
            // Detection results grid
            Row(modifier = Modifier.fillMaxWidth()) {
                Column(modifier = Modifier.weight(1f)) {
                    Text("Chipset", style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                    Text(chipsetName, style = MaterialTheme.typography.bodyMedium)
                }
                Column(modifier = Modifier.weight(1f)) {
                    Text("Radio Type", style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                    Text(radioType, style = MaterialTheme.typography.bodyMedium)
                }
            }
            
            Spacer(Modifier.height(8.dp))
            
            Row(modifier = Modifier.fillMaxWidth()) {
                Column(modifier = Modifier.weight(1f)) {
                    Text("AT Method", style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                    Text(atMethod, style = MaterialTheme.typography.bodyMedium)
                }
                Column(modifier = Modifier.weight(1f)) {
                    Text("SMS Strategy", style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                    Text(smsStrategy, style = MaterialTheme.typography.bodyMedium)
                }
            }
            
            // Modem paths
            if (modemPaths.isNotEmpty()) {
                Spacer(Modifier.height(12.dp))
                Text("Detected Modem Paths:", style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                modemPaths.take(3).forEach { path ->
                    Text("• $path", style = MaterialTheme.typography.bodySmall)
                }
                if (modemPaths.size > 3) {
                    Text("• ... and ${modemPaths.size - 3} more", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                }
            }
            
            // Detection progress log
            if (detectionLog.isNotEmpty()) {
                Spacer(Modifier.height(12.dp))
                Card(
                    modifier = Modifier.fillMaxWidth(),
                    colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)
                ) {
                    Column(modifier = Modifier.padding(8.dp)) {
                        detectionLog.takeLast(5).forEach { line ->
                            Text(line, style = MaterialTheme.typography.bodySmall)
                        }
                    }
                }
            }

            if (atCapabilityResults.isNotEmpty()) {
                Spacer(Modifier.height(12.dp))
                Text("AT Capability Scan", style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                Spacer(Modifier.height(4.dp))
                atCapabilityResults.take(4).forEach { result ->
                    val statusText = when {
                        !result.exists -> "Missing"
                        !result.accessible -> "Inaccessible"
                        result.responded -> "AT OK"
                        else -> "No response"
                    }
                    val color = when {
                        result.responded -> MaterialTheme.colorScheme.primary
                        !result.exists -> MaterialTheme.colorScheme.onSurfaceVariant
                        else -> MaterialTheme.colorScheme.error
                    }
                    Column(modifier = Modifier.fillMaxWidth().padding(vertical = 4.dp)) {
                        Text("${result.devicePath} (${result.chipset.displayName})", style = MaterialTheme.typography.bodySmall)
                        Text(statusText, style = MaterialTheme.typography.bodySmall, color = color)
                    }
                }
                if (atCapabilityResults.size > 4) {
                    Text("…and ${atCapabilityResults.size - 4} more", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                }
            }
            
            Spacer(Modifier.height(12.dp))
            
            // Action buttons
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                Button(
                    onClick = {
                        scope.launch {
                            isDetecting = true
                            withContext(Dispatchers.IO) {
                                DeviceInfoManager.refresh(context)
                            }
                            isDetecting = false
                        }
                    },
                    modifier = Modifier.weight(1f),
                    enabled = !isDetecting
                ) {
                    if (isDetecting) {
                        CircularProgressIndicator(modifier = Modifier.size(16.dp), strokeWidth = 2.dp)
                    } else {
                        Icon(Icons.Default.Refresh, contentDescription = null)
                    }
                    Spacer(Modifier.width(8.dp))
                    Text(if (isDetecting) "Detecting..." else "Detect Device")
                }
            }
            
            Spacer(Modifier.height(8.dp))
            Text(
                "Detects device chipset, radio type, and optimal SMS strategy for AT commands.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
    }
}
