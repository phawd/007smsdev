package com.zerosms.testing.ui.screens.settings

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SettingsScreen(
    onNavigateBack: () -> Unit
) {
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
                        
                        Divider(modifier = Modifier.padding(vertical = 8.dp))
                        
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
                            onClick = { /* Export logs */ },
                            modifier = Modifier.fillMaxWidth()
                        ) {
                            Icon(Icons.Default.FileDownload, contentDescription = null)
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
                            "ZeroSMS Testing Suite",
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
    
    LaunchedEffect(Unit) {
        // Check root and AT commands
        // In production, inject SmsManagerWrapper via DI
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
        }
    }
}

@Composable
fun MmscConfigCard() {
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
                onClick = { /* Save MMSC config */ },
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
