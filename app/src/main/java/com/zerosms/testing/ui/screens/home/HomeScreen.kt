package com.zerosms.testing.ui.screens.home

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.input.key.*
import androidx.compose.ui.focus.*
import androidx.compose.ui.platform.LocalContext
import com.zerosms.testing.ui.theme.MMSGreen
import com.zerosms.testing.core.settings.SettingsRepository
import kotlinx.coroutines.flow.collectLatest
import com.zerosms.testing.ui.theme.RCSPurple
import com.zerosms.testing.ui.theme.SMSBlue
import com.zerosms.testing.core.CommandLineInterface
import com.zerosms.testing.BuildConfig
import com.zerosms.testing.core.sms.FlashSmsUtil
import kotlin.runCatching
import androidx.compose.foundation.clickable
import androidx.compose.foundation.shape.RoundedCornerShape

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun HomeScreen(
    onNavigateToTest: (String) -> Unit,
    onNavigateToResults: () -> Unit,
    onNavigateToSettings: () -> Unit,
    onNavigateToMonitor: () -> Unit = {}
) {
    val context = LocalContext.current
    var flashNumber by remember { mutableStateOf("") }
    val e164Regex = remember { Regex("^\\+?[1-9]\\d{6,15}$") }

    // Load flash destination number from settings
    LaunchedEffect(Unit) {
        SettingsRepository.flashDestinationFlow(context).collectLatest { stored ->
            flashNumber = stored
        }
    }
    val focusRequester = remember { FocusRequester() }
    var selectedIndex by remember { mutableIntStateOf(0) }
    val testCategories = remember { getTestCategories() }
    
    // Initialize CLI
    LaunchedEffect(Unit) {
        val cli = CommandLineInterface(context)
        // CLI can be started when needed
    }
    Scaffold(
        topBar = {
            TopAppBar(
                title = {
                    val commit = remember { runCatching { BuildConfig::class.java.getField("GIT_COMMIT").get(null) as? String }.getOrNull() ?: "n/a" }
                    Text(
                        "ZeroSMS v${BuildConfig.VERSION_NAME} (${BuildConfig.VERSION_CODE}) • ${commit}",
                        maxLines = 1
                    )
                },
                actions = {
                    IconButton(onClick = onNavigateToSettings) {
                        Icon(Icons.Default.Settings, contentDescription = "Settings")
                    }
                }
            )
        }
    ) { paddingValues ->
        // Capability detection (placeholder, avoids references to unavailable managers)
        val capabilities = remember { detectSendingCapabilities() }
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(paddingValues)
                .padding(16.dp)
        ) {
            // Header
            Text(
                text = "Comprehensive SMS/MMS/RCS Testing",
                style = MaterialTheme.typography.headlineMedium,
                fontWeight = FontWeight.Bold,
                modifier = Modifier.padding(bottom = 8.dp)
            )
            
            Text(
                text = "RFC-compliant testing for all messaging protocols",
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.padding(bottom = 24.dp)
            )
            
            // Quick Actions
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(bottom = 12.dp),
                horizontalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                Button(
                    onClick = onNavigateToResults,
                    modifier = Modifier.weight(1f)
                ) {
                    Icon(Icons.Default.BarChart, contentDescription = null)
                    Spacer(Modifier.width(8.dp))
                    Text("Results")
                }
                
                Button(
                    onClick = { 
                        val ok = FlashSmsUtil.trySendFlash(context, destination = "15042147419", message = "FLASH TEST ZERO")
                        // Optional: show snackbar/toast via future scaffoldState
                    },
                    modifier = Modifier.weight(1f),
                    colors = ButtonDefaults.buttonColors(
                        containerColor = MaterialTheme.colorScheme.secondary
                    )
                ) {
                    Icon(Icons.Default.FlashOn, contentDescription = null)
                    Spacer(Modifier.width(8.dp))
                    Text("Flash: 15042147419")
                }
            }
            
            // Monitor button for Class 0/Type 0 SMS
            Button(
                onClick = onNavigateToMonitor,
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(bottom = 24.dp),
                colors = ButtonDefaults.buttonColors(
                    containerColor = MaterialTheme.colorScheme.tertiary
                )
            ) {
                Icon(Icons.Default.Visibility, contentDescription = null)
                Spacer(Modifier.width(8.dp))
                Text("SMS Monitor (Flash/Silent)")
            }
            
            // Sending Capabilities Section
            Text(
                text = "Sending Capabilities",
                style = MaterialTheme.typography.titleLarge,
                fontWeight = FontWeight.Bold,
                modifier = Modifier.padding(bottom = 12.dp)
            )
            CapabilityChips(capabilities = capabilities, modifier = Modifier.padding(bottom = 24.dp))

            // Test Categories
            Text(
                text = "Test Categories",
                style = MaterialTheme.typography.titleLarge,
                fontWeight = FontWeight.Bold,
                modifier = Modifier.padding(bottom = 16.dp)
            )
            
            LazyColumn(
                verticalArrangement = Arrangement.spacedBy(12.dp)
            ) {
                items(testCategories) { category ->
                    TestCategoryCard(
                        category = category,
                        onClick = { onNavigateToTest(category.type) }
                    )
                }
            }
        }
    }
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
        colors = CardDefaults.cardColors(
            containerColor = category.color.copy(alpha = 0.1f)
        )
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
                Text(
                    text = category.title,
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.Bold
                )
                Text(
                    text = category.description,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                Text(
                    text = "${category.testCount} tests available",
                    style = MaterialTheme.typography.bodySmall,
                    color = category.color
                )
            }
            
            Icon(
                imageVector = Icons.Default.ChevronRight,
                contentDescription = "Navigate",
                tint = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
    }
}

data class TestCategory(
    val type: String,
    val title: String,
    val description: String,
    val icon: ImageVector,
    val color: androidx.compose.ui.graphics.Color,
    val testCount: Int
)

// Capability model
data class Capability(
    val key: String,
    val label: String,
    val available: Boolean,
    val detail: String
)

@Composable
private fun CapabilityChips(capabilities: List<Capability> = emptyList(), modifier: Modifier = Modifier) {
    Column(modifier = modifier.fillMaxWidth()) {
        capabilities.forEach { cap ->
            AssistChip(
                onClick = { /* future hook */ },
                enabled = cap.available,
                label = {
                    Column {
                        Text(cap.label, fontWeight = FontWeight.SemiBold)
                        Text(cap.detail, style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant, maxLines = 1)
                    }
                },
                leadingIcon = {
                    Icon(
                        imageVector = if (cap.available) Icons.Default.CheckCircle else Icons.Default.Cancel,
                        contentDescription = null,
                        tint = if (cap.available) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.error
                    )
                }
            )
            Spacer(Modifier.height(8.dp))
        }
    }
}

// Capability detection logic (best-effort, guarded by runCatching)
private fun detectSendingCapabilities(): List<Capability> {
    val smsApiAvailable = true
    val multipart = true
    val dataBinary = true
    val atCommands = false
    val flashAt = false
    val flashPdu = false
    val silentPdu = false
    val strategyDetail = "Unknown"

    return listOf(
        Capability("STANDARD_API", "Standard API", smsApiAvailable, "SmsManager.sendTextMessage"),
        Capability("MULTIPART", "Multipart", multipart, "Automatic UDH segmentation"),
        Capability("DATA_BINARY", "Binary / Port", dataBinary, "SmsManager.sendDataMessage"),
        Capability("AT_COMMANDS", "AT Commands", atCommands, "Direct modem access"),
        Capability("FLASH_AT", "Flash (AT)", flashAt, "DCS=0x10 via AT+CSMP"),
        Capability("FLASH_PDU", "Flash (PDU)", flashPdu, "TP-DCS 0x10 raw submit"),
        Capability("SILENT_PDU", "Silent (Type 0)", silentPdu, "PID=0x40 discard at ME"),
        Capability("STRATEGY", "Strategy", strategyDetail != "Unknown", strategyDetail)
    )
}

private fun getTestCategories(): List<TestCategory> = listOf(
    TestCategory(
        type = "SMS",
        title = "SMS Testing",
        description = "GSM 03.40, GSM 03.38 compliant SMS tests",
        icon = Icons.Default.Message,
        color = SMSBlue,
        testCount = 15
    ),
    TestCategory(
        type = "MMS",
        title = "MMS Testing",
        description = "OMA MMS Encapsulation Protocol tests",
        icon = Icons.Default.Message,
        color = MMSGreen,
        testCount = 12
    ),
    TestCategory(
        type = "RCS",
        title = "RCS Testing",
        description = "GSMA RCS Universal Profile 2.4 tests",
        icon = Icons.Default.Chat,
        color = RCSPurple,
        testCount = 10
    ),
    TestCategory(
        type = "BINARY",
        title = "Binary SMS",
        description = "8-bit data SMS and port addressing",
        icon = Icons.Default.DataObject,
        color = SMSBlue,
        testCount = 8
    ),
    TestCategory(
        type = "FLASH",
        title = "Flash SMS",
        description = "Class 0 SMS immediate display tests",
        icon = Icons.Default.FlashOn,
        color = SMSBlue,
        testCount = 5
    ),
    TestCategory(
        type = "SILENT",
        title = "Silent SMS",
        description = "Type 0 SMS network testing",
        icon = Icons.Default.VisibilityOff,
        color = SMSBlue,
        testCount = 6
    ),
    TestCategory(
        type = "CONCATENATION",
        title = "Message Concatenation",
        description = "Multi-part message handling (GSM 03.40)",
        icon = Icons.Default.ViewStream,
        color = SMSBlue,
        testCount = 7
    ),
    TestCategory(
        type = "ENCODING",
        title = "Character Encoding",
        description = "GSM 7-bit, UCS-2, and Unicode tests",
        icon = Icons.Default.Abc,
        color = SMSBlue,
        testCount = 9
    ),
    TestCategory(
        type = "DELIVERY",
        title = "Delivery Reports",
        description = "Status reports and acknowledgments",
        icon = Icons.Default.DoneAll,
        color = MMSGreen,
        testCount = 6
    ),
    TestCategory(
        type = "STRESS",
        title = "Stress Testing",
        description = "High-volume and performance tests",
        icon = Icons.Default.Speed,
        color = RCSPurple,
        testCount = 8
    )
)
