package com.smstest.app.ui.screens.settings

import android.widget.Toast
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
import com.smstest.app.core.at.AtCapabilityScanResult
import com.smstest.app.core.at.AtCommandManager
import com.smstest.app.core.device.DeviceInfoManager
import com.smstest.app.core.device.SmsStrategy
import com.smstest.app.core.export.LogExporter
import com.smstest.app.core.qualcomm.QualcommDiagManager
import com.smstest.app.core.qualcomm.QualcommDiagProfile
import com.smstest.app.core.settings.SettingsRepository
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SettingsScreen(
    onNavigateBack: () -> Unit
) {
    val context = LocalContext.current
    var autoDeliveryReport by remember { mutableStateOf(true) }
    var autoReadReport by remember { mutableStateOf(false) }
    var defaultEncoding by remember { mutableStateOf("AUTO") }
    var logLevel by remember { mutableStateOf("INFO") }
    
    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Settings") },
                navigationIcon = {
                    IconButton(onClick = onNavigateBack) {
                            Icon(Icons.Default.ArrowBack, contentDescription = "Back")
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
                Text(
                    "Messaging Options",
                    style = MaterialTheme.typography.titleLarge
                )
            }
            
            item {
                Card(modifier = Modifier.fillMaxWidth()) {
                    Column(modifier = Modifier.padding(16.dp)) {
                        SettingRow(
                            title = "Automatic Delivery Reports",
                            subtitle = "Request delivery confirmation for all messages",
                            checked = autoDeliveryReport,
                            onCheckedChange = { autoDeliveryReport = it }
                        )
                        
                        HorizontalDivider(modifier = Modifier.padding(vertical = 8.dp))
                        
                        SettingRow(
                            title = "Automatic Read Reports",
                            subtitle = "Request read receipts for all messages",
                            checked = autoReadReport,
                            onCheckedChange = { autoReadReport = it }
                        )
                    }
                }
            }
            
            item {
                Text(
                    "Default Parameters",
                    style = MaterialTheme.typography.titleLarge
                )
            }
            
            item {
                Card(modifier = Modifier.fillMaxWidth()) {
                    Column(modifier = Modifier.padding(16.dp)) {
                        Text(
                            "Default Encoding",
                            style = MaterialTheme.typography.titleSmall
                        )
                        Spacer(Modifier.height(8.dp))
                        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                            listOf("AUTO", "GSM_7BIT", "UCS2").forEach { encoding ->
                                FilterChip(
                                    selected = defaultEncoding == encoding,
                                    onClick = { defaultEncoding = encoding },
                                    label = { Text(encoding) }
                                )
                            }
                        }
                    }
                }
            }
            
            item {
                Text(
                    "Advanced Features",
                    style = MaterialTheme.typography.titleLarge
                )
            }
            
            item {
                RootAccessCard()
            }

            item {
                DeviceDetectionCard()
            }
            
            item {
                MmscConfigCard()
            }
            
            item {
                Text(
                    "Testing & Debugging",
                    style = MaterialTheme.typography.titleLarge
                )
            }
            
            item {
                Card(modifier = Modifier.fillMaxWidth()) {
                    Column(modifier = Modifier.padding(16.dp)) {
                        Text(
                            "Log Level",
                            style = MaterialTheme.typography.titleSmall
                        )
                        Spacer(Modifier.height(8.dp))
                        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                            listOf("DEBUG", "INFO", "WARN", "ERROR").forEach { level ->
                                FilterChip(
                                    selected = logLevel == level,
                                    onClick = { logLevel = level },
                                    label = { Text(level) }
                                )
                            }
                        }
                        
                        Spacer(Modifier.height(16.dp))
                        
                        Button(
                            onClick = {
                                val success = LogExporter.exportActivityLogs(context)
                                if (!success) {
                                    Toast.makeText(context, "No logs to export", Toast.LENGTH_SHORT).show()
                                }
                            },
                            modifier = Modifier.fillMaxWidth()
                        ) {
                            Icon(Icons.Default.Download, contentDescription = null)
                            Spacer(Modifier.width(8.dp))
                            Text("Export Logs")
                        }
                    }
                }
            }
            
            item {
                Text(
                    "RFC Compliance",
                    style = MaterialTheme.typography.titleLarge
                )
            }
            
            item {
                Card(
                    modifier = Modifier.fillMaxWidth(),
                    colors = CardDefaults.cardColors(
                        containerColor = MaterialTheme.colorScheme.secondaryContainer
                    )
                ) {
                    Column(modifier = Modifier.padding(16.dp)) {
                        Text(
                            "Standards Implemented",
                            style = MaterialTheme.typography.titleSmall
                        )
                        Spacer(Modifier.height(8.dp))
                        listOf(
                            "GSM 03.40 - SMS Point-to-Point",
                            "GSM 03.38 - Character Set",
                            "3GPP TS 23.040 - Technical Realization",
                            "OMA MMS Encapsulation Protocol",
                            "WAP-209-MMSEncapsulation",
                            "GSMA RCS Universal Profile 2.4",
                            "RFC 2046 - MIME Media Types",
                            "RFC 4975 - MSRP Protocol"
                        ).forEach { rfc ->
                            Text(
                                "• $rfc",
                                style = MaterialTheme.typography.bodySmall
                            )
                        }
                    }
                }
            }
            
            item {
                Text(
                    "About",
                    style = MaterialTheme.typography.titleLarge
                )
            }
            
            item {
                Card(modifier = Modifier.fillMaxWidth()) {
                    Column(
                        modifier = Modifier.padding(16.dp),
                        horizontalAlignment = Alignment.CenterHorizontally
                    ) {
                        Text(
                            "SMS Test Testing Suite",
                            style = MaterialTheme.typography.titleMedium
                        )
                        Text(
                            "Version 1.0.0",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                        Spacer(Modifier.height(8.dp))
                        Text(
                            "Comprehensive SMS/MMS/RCS testing with full RFC compliance",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                }
            }
        }
    }
}

@Composable
fun SettingRow(
    title: String,
    subtitle: String,
    checked: Boolean,
    onCheckedChange: (Boolean) -> Unit
) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically
    ) {
        Column(modifier = Modifier.weight(1f)) {
            Text(
                text = title,
                style = MaterialTheme.typography.bodyLarge
            )
            Text(
                text = subtitle,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
        Switch(
            checked = checked,
            onCheckedChange = onCheckedChange
        )
    }
}

@Composable
fun RootAccessCard() {
    var rootAvailable by remember { mutableStateOf<Boolean?>(null) }
    var atCommandsAvailable by remember { mutableStateOf<Boolean?>(null) }
    var modemDevice by remember { mutableStateOf<String?>(null) }
    
    // Qualcomm Diag states
    var diagUsbConfig by remember { mutableStateOf<String?>(null) }
    var diagStatusMessage by remember { mutableStateOf("Checking Qualcomm diagnostic USB config...") }
    var diagInProgress by remember { mutableStateOf(false) }
    val diagProfiles = remember { QualcommDiagManager.getPresetProfiles() }
    var selectedDiagProfileId by remember { mutableStateOf(diagProfiles.firstOrNull()?.id) }
    val scope = rememberCoroutineScope()

    val selectedDiagProfile: QualcommDiagProfile? = remember(selectedDiagProfileId, diagProfiles) {
        diagProfiles.firstOrNull { it.id == selectedDiagProfileId }
    }

    LaunchedEffect(Unit) {
        // Check root and AT commands
        // In production, inject SmsManagerWrapper via DI
        
        scope.launch {
            val config = withContext(Dispatchers.IO) { QualcommDiagManager.getActiveUsbConfig() }
            diagUsbConfig = config
            diagStatusMessage = config?.let { "USB config: $it" } ?: "Qualcomm USB config unavailable"
        }
    }
    
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(
            containerColor = when (rootAvailable) {
                true -> MaterialTheme.colorScheme.primaryContainer
                false -> MaterialTheme.colorScheme.errorContainer
                null -> MaterialTheme.colorScheme.surfaceVariant
            }
        )
    ) {
        Column(modifier = Modifier.padding(16.dp)) {
            Row(
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                Icon(
                    if (rootAvailable == true) Icons.Default.CheckCircle else Icons.Default.Warning,
                    contentDescription = null
                )
                Text(
                    "Root Access & AT Commands",
                    style = MaterialTheme.typography.titleMedium
                )
            }
            
            Spacer(Modifier.height(12.dp))
            
            StatusRow("Root Access", rootAvailable)
            StatusRow("AT Commands", atCommandsAvailable)
            
            modemDevice?.let {
                Spacer(Modifier.height(8.dp))
                Text(
                    "Modem Device: $it",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
            
            Spacer(Modifier.height(12.dp))
            
            Text(
                "AT commands enable direct modem access for sending Class 0 (Flash) and Type 0 (Silent) SMS. Root access is required.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
            
            Spacer(Modifier.height(12.dp))
            
            Button(
                onClick = { /* Reinitialize AT commands */ },
                modifier = Modifier.fillMaxWidth()
            ) {
                Icon(Icons.Default.Refresh, contentDescription = null)
                Spacer(Modifier.width(8.dp))
                Text("Initialize AT Commands")
            }
            
            Spacer(Modifier.height(16.dp))
            HorizontalDivider()
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
            Row(
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                Icon(Icons.Default.Search, contentDescription = null)
                Text(
                    "Device Detection",
                    style = MaterialTheme.typography.titleMedium
                )
            }
            
            Spacer(Modifier.height(12.dp))
            
            if (manufacturer.isNotEmpty()) {
                Text("Device: $manufacturer $model", style = MaterialTheme.typography.bodyMedium)
                Spacer(Modifier.height(4.dp))
            }
            
            StatusRow("Chipset", if (chipsetName != "Not detected") true else null)
            if (chipsetName != "Not detected") {
                Text(chipsetName, style = MaterialTheme.typography.bodySmall, modifier = Modifier.padding(start = 8.dp))
            }
            
            Spacer(Modifier.height(8.dp))
            Text("SMS Strategy: $smsStrategy", style = MaterialTheme.typography.bodyMedium)
            
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
            
            Button(
                onClick = { 
                    scope.launch {
                        DeviceInfoManager.detectDevice()
                    }
                },
                modifier = Modifier.fillMaxWidth(),
                enabled = !isDetecting
            ) {
                if (isDetecting) {
                    CircularProgressIndicator(
                        modifier = Modifier.size(24.dp),
                        color = MaterialTheme.colorScheme.onPrimary,
                        strokeWidth = 2.dp
                    )
                    Spacer(Modifier.width(8.dp))
                    Text("Detecting...")
                } else {
                    Icon(Icons.Default.Refresh, contentDescription = null)
                    Spacer(Modifier.width(8.dp))
                    Text("Redetect Device")
                }
            }
        }
    }
}

@Composable
fun MmscConfigCard() {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var showCarrierPresets by remember { mutableStateOf(false) }
    var currentMmscUrl by remember { mutableStateOf("") }
    var currentProxy by remember { mutableStateOf("") }
    var currentPort by remember { mutableStateOf("80") }
    
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(modifier = Modifier.padding(16.dp)) {
            Row(
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                Icon(Icons.Default.Cloud, contentDescription = null)
                Text(
                    "MMSC Configuration",
                    style = MaterialTheme.typography.titleMedium
                )
            }
            
            Spacer(Modifier.height(12.dp))
            
            OutlinedTextField(
                value = currentMmscUrl,
                onValueChange = { currentMmscUrl = it },
                label = { Text("MMSC URL") },
                placeholder = { Text("http://mmsc.example.com") },
                modifier = Modifier.fillMaxWidth()
            )
            
            Spacer(Modifier.height(8.dp))
            
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                OutlinedTextField(
                    value = currentProxy,
                    onValueChange = { currentProxy = it },
                    label = { Text("Proxy") },
                    placeholder = { Text("Optional") },
                    modifier = Modifier.weight(1f)
                )
                
                OutlinedTextField(
                    value = currentPort,
                    onValueChange = { currentPort = it },
                    label = { Text("Port") },
                    placeholder = { Text("80") },
                    modifier = Modifier.weight(1f)
                )
            }
            
            Spacer(Modifier.height(12.dp))
            
            Button(
                onClick = { showCarrierPresets = !showCarrierPresets },
                modifier = Modifier.fillMaxWidth(),
                colors = ButtonDefaults.outlinedButtonColors()
            ) {
                Icon(Icons.Default.List, contentDescription = null)
                Spacer(Modifier.width(8.dp))
                Text("Carrier Presets")
            }
            
            Spacer(Modifier.height(8.dp))
            
            Button(
                onClick = { 
                    scope.launch { 
                        SettingsRepository.setMmscConfig(context, currentMmscUrl, currentProxy, currentPort) 
                        Toast.makeText(context, "Configuration saved", Toast.LENGTH_SHORT).show()
                    } 
                },
                modifier = Modifier.fillMaxWidth()
            ) {
                Icon(Icons.Default.Save, contentDescription = null)
                Spacer(Modifier.width(8.dp))
                Text("Save Configuration")
            }
        }
    }
}

@Composable
fun StatusRow(label: String, status: Boolean?) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically
    ) {
        Text(
            text = label,
            style = MaterialTheme.typography.bodyMedium
        )
        
        AssistChip(
            onClick = {},
            label = { 
                Text(
                    when (status) {
                        true -> "Available"
                        false -> "Unavailable"
                        null -> "Checking..."
                    }
                )
            },
            colors = AssistChipDefaults.assistChipColors(
                containerColor = when (status) {
                    true -> MaterialTheme.colorScheme.primary
                    false -> MaterialTheme.colorScheme.error
                    null -> MaterialTheme.colorScheme.surfaceVariant
                },
                labelColor = when (status) {
                    true -> MaterialTheme.colorScheme.onPrimary
                    false -> MaterialTheme.colorScheme.onError
                    null -> MaterialTheme.colorScheme.onSurfaceVariant
                }
            )
        )
    }
}
