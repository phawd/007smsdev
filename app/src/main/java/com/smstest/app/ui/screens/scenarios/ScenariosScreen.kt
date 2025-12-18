package com.smstest.app.ui.screens.scenarios

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
import com.smstest.app.core.model.*

/**
 * Test Scenarios Browser Screen
 * 
 * Browse all enumerated test scenarios with filtering and configuration
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ScenariosScreen(
    onNavigateBack: () -> Unit,
    onRunScenario: (TestScenario) -> Unit
) {
    var selectedCategory by remember { mutableStateOf<TestCategory?>(null) }
    var selectedDifficulty by remember { mutableStateOf<TestDifficulty?>(null) }
    var showRootOnly by remember { mutableStateOf(false) }
    var searchQuery by remember { mutableStateOf("") }
    var expandedScenario by remember { mutableStateOf<String?>(null) }
    
    // Combine all scenarios
    val allScenarios = remember {
        TestScenarios.getAllScenarios() + TestScenariosExtended.getAllExtendedScenarios()
    }
    
    // Filter scenarios
    val filteredScenarios = remember(selectedCategory, selectedDifficulty, showRootOnly, searchQuery) {
        allScenarios.filter { scenario ->
            (selectedCategory == null || scenario.category == selectedCategory) &&
            (selectedDifficulty == null || scenario.difficulty == selectedDifficulty) &&
            (!showRootOnly || scenario.requiresRoot) &&
            (searchQuery.isEmpty() || 
                scenario.name.contains(searchQuery, ignoreCase = true) ||
                scenario.id.contains(searchQuery, ignoreCase = true) ||
                scenario.description.contains(searchQuery, ignoreCase = true))
        }
    }
    
    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Test Scenarios (${filteredScenarios.size})") },
                navigationIcon = {
                    IconButton(onClick = onNavigateBack) {
                        Icon(Icons.Filled.ArrowBack, contentDescription = "Back")
                    }
                },
                actions = {
                    IconButton(onClick = { /* Export scenarios */ }) {
                        Icon(Icons.Filled.Download, contentDescription = "Export")
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
            // Search bar
            OutlinedTextField(
                value = searchQuery,
                onValueChange = { searchQuery = it },
                label = { Text("Search scenarios") },
                leadingIcon = { Icon(Icons.Filled.Search, null) },
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(16.dp)
            )
            
            // Filters
            FilterSection(
                selectedCategory = selectedCategory,
                onCategoryChange = { selectedCategory = it },
                selectedDifficulty = selectedDifficulty,
                onDifficultyChange = { selectedDifficulty = it },
                showRootOnly = showRootOnly,
                onRootOnlyChange = { showRootOnly = it }
            )
            
            // Statistics
            ScenarioStats(
                total = filteredScenarios.size,
                byDifficulty = filteredScenarios.groupingBy { it.difficulty }.eachCount(),
                rootRequired = filteredScenarios.count { it.requiresRoot },
                carrierDependent = filteredScenarios.count { it.carrierDependent }
            )
            
            // Scenario list
            LazyColumn(
                modifier = Modifier.fillMaxSize(),
                contentPadding = PaddingValues(16.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                items(filteredScenarios) { scenario ->
                    ScenarioCard(
                        scenario = scenario,
                        isExpanded = expandedScenario == scenario.id,
                        onExpandToggle = {
                            expandedScenario = if (expandedScenario == scenario.id) null else scenario.id
                        },
                        onRun = { onRunScenario(scenario) }
                    )
                }
            }
        }
    }
}

@Composable
fun FilterSection(
    selectedCategory: TestCategory?,
    onCategoryChange: (TestCategory?) -> Unit,
    selectedDifficulty: TestDifficulty?,
    onDifficultyChange: (TestDifficulty?) -> Unit,
    showRootOnly: Boolean,
    onRootOnlyChange: (Boolean) -> Unit
) {
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 16.dp)
    ) {
        Text(
            "Filter by Category",
            style = MaterialTheme.typography.labelMedium,
            modifier = Modifier.padding(bottom = 8.dp)
        )
        
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            FilterChip(
                selected = selectedCategory == null,
                onClick = { onCategoryChange(null) },
                label = { Text("All") }
            )
            FilterChip(
                selected = selectedCategory == TestCategory.SMS_TEXT,
                onClick = { onCategoryChange(TestCategory.SMS_TEXT) },
                label = { Text("SMS Text") }
            )
            FilterChip(
                selected = selectedCategory == TestCategory.SMS_FLASH,
                onClick = { onCategoryChange(TestCategory.SMS_FLASH) },
                label = { Text("Flash") }
            )
            FilterChip(
                selected = selectedCategory == TestCategory.SMS_SILENT,
                onClick = { onCategoryChange(TestCategory.SMS_SILENT) },
                label = { Text("Silent") }
            )
        }
        
        Spacer(Modifier.height(16.dp))
        
        Text(
            "Filter by Difficulty",
            style = MaterialTheme.typography.labelMedium,
            modifier = Modifier.padding(bottom = 8.dp)
        )
        
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            FilterChip(
                selected = selectedDifficulty == null,
                onClick = { onDifficultyChange(null) },
                label = { Text("All") }
            )
            TestDifficulty.values().forEach { difficulty ->
                FilterChip(
                    selected = selectedDifficulty == difficulty,
                    onClick = { onDifficultyChange(difficulty) },
                    label = { Text(difficulty.name) }
                )
            }
        }
        
        Spacer(Modifier.height(16.dp))
        
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(8.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            FilterChip(
                selected = showRootOnly,
                onClick = { onRootOnlyChange(!showRootOnly) },
                label = { Text("Root Required Only") },
                leadingIcon = { Icon(Icons.Filled.Security, null) }
            )
        }
        
        Divider(modifier = Modifier.padding(vertical = 16.dp))
    }
}

@Composable
fun ScenarioStats(
    total: Int,
    byDifficulty: Map<TestDifficulty, Int>,
    rootRequired: Int,
    carrierDependent: Int
) {
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 16.dp, vertical = 8.dp),
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
            StatColumn("Total", total)
            StatColumn("Basic", byDifficulty[TestDifficulty.BASIC] ?: 0)
            StatColumn("Intermediate", byDifficulty[TestDifficulty.INTERMEDIATE] ?: 0)
            StatColumn("Advanced", byDifficulty[TestDifficulty.ADVANCED] ?: 0)
            StatColumn("Expert", byDifficulty[TestDifficulty.EXPERT] ?: 0)
        }
    }
}

@Composable
fun StatColumn(label: String, count: Int) {
    Column(horizontalAlignment = Alignment.CenterHorizontally) {
        Text(
            text = count.toString(),
            style = MaterialTheme.typography.headlineSmall,
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
fun ScenarioCard(
    scenario: TestScenario,
    isExpanded: Boolean,
    onExpandToggle: () -> Unit,
    onRun: () -> Unit
) {
    Card(
        onClick = onExpandToggle,
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(
            containerColor = when (scenario.difficulty) {
                TestDifficulty.BASIC -> MaterialTheme.colorScheme.surfaceVariant
                TestDifficulty.INTERMEDIATE -> MaterialTheme.colorScheme.secondaryContainer.copy(alpha = 0.3f)
                TestDifficulty.ADVANCED -> MaterialTheme.colorScheme.tertiaryContainer.copy(alpha = 0.3f)
                TestDifficulty.EXPERT -> MaterialTheme.colorScheme.errorContainer.copy(alpha = 0.2f)
            }
        )
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(16.dp)
        ) {
            // Header
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.Top
            ) {
                Column(modifier = Modifier.weight(1f)) {
                    Row(
                        horizontalArrangement = Arrangement.spacedBy(8.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Text(
                            text = scenario.id,
                            style = MaterialTheme.typography.labelLarge,
                            fontWeight = FontWeight.Bold,
                            color = MaterialTheme.colorScheme.primary
                        )
                        
                        if (scenario.requiresRoot) {
                            AssistChip(
                                onClick = {},
                                label = { Text("ROOT", style = MaterialTheme.typography.labelSmall) },
                                colors = AssistChipDefaults.assistChipColors(
                                    containerColor = MaterialTheme.colorScheme.error,
                                    labelColor = MaterialTheme.colorScheme.onError
                                )
                            )
                        }
                        
                        if (scenario.carrierDependent) {
                            AssistChip(
                                onClick = {},
                                label = { Text("CARRIER", style = MaterialTheme.typography.labelSmall) },
                                colors = AssistChipDefaults.assistChipColors(
                                    containerColor = MaterialTheme.colorScheme.tertiary
                                )
                            )
                        }
                    }
                    
                    Spacer(Modifier.height(4.dp))
                    
                    Text(
                        text = scenario.name,
                        style = MaterialTheme.typography.titleMedium,
                        fontWeight = FontWeight.Bold
                    )
                    
                    Text(
                        text = scenario.description,
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
                
                Icon(
                    imageVector = if (isExpanded) Icons.Filled.ExpandLess else Icons.Filled.ExpandMore,
                    contentDescription = if (isExpanded) "Collapse" else "Expand"
                )
            }
            
            Spacer(Modifier.height(8.dp))
            
            // Badges
            Row(
                horizontalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                AssistChip(
                    onClick = {},
                    label = { Text(scenario.difficulty.name) },
                    colors = AssistChipDefaults.assistChipColors(
                        containerColor = when (scenario.difficulty) {
                            TestDifficulty.BASIC -> MaterialTheme.colorScheme.primary
                            TestDifficulty.INTERMEDIATE -> MaterialTheme.colorScheme.secondary
                            TestDifficulty.ADVANCED -> MaterialTheme.colorScheme.tertiary
                            TestDifficulty.EXPERT -> MaterialTheme.colorScheme.error
                        }
                    )
                )
                
                AssistChip(
                    onClick = {},
                    label = { Text(scenario.messageType.name) }
                )
            }
            
            // Expanded details
            if (isExpanded) {
                Divider(modifier = Modifier.padding(vertical = 12.dp))
                
                ScenarioDetails(scenario)
                
                Spacer(Modifier.height(12.dp))
                
                Button(
                    onClick = onRun,
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Icon(Icons.Filled.PlayArrow, contentDescription = null)
                    Spacer(Modifier.width(8.dp))
                    Text("Run This Scenario")
                }
            }
        }
    }
}

@Composable
fun ScenarioDetails(scenario: TestScenario) {
    Column(
        verticalArrangement = Arrangement.spacedBy(8.dp)
    ) {
        DetailRow("Category", scenario.category.name)
        DetailRow("Message Type", scenario.messageType.name)
        
        if (scenario.rfcReferences.isNotEmpty()) {
            DetailRow("RFC References", scenario.rfcReferences.joinToString(", "))
        }
        
        Text(
            "Default Configuration:",
            style = MaterialTheme.typography.labelMedium,
            fontWeight = FontWeight.Bold
        )
        
        Column(
            modifier = Modifier.padding(start = 16.dp),
            verticalArrangement = Arrangement.spacedBy(4.dp)
        ) {
            DetailRow("Encoding", scenario.defaultConfig.encoding.name)
            DetailRow("Message Class", scenario.defaultConfig.messageClass.name)
            DetailRow("Priority", scenario.defaultConfig.priority.name)
            DetailRow("Delivery Report", if (scenario.defaultConfig.deliveryReport) "Yes" else "No")
            DetailRow("Repeat Count", scenario.defaultConfig.repeatCount.toString())
            
            if (scenario.defaultConfig.useAtCommands) {
                DetailRow("AT Commands", "ENABLED", MaterialTheme.colorScheme.error)
            }
            
            if (scenario.defaultConfig.testBody.isNotEmpty()) {
                Spacer(Modifier.height(4.dp))
                Text(
                    "Test Body:",
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                Text(
                    scenario.defaultConfig.testBody.take(100) + 
                        if (scenario.defaultConfig.testBody.length > 100) "..." else "",
                    style = MaterialTheme.typography.bodySmall,
                    modifier = Modifier.padding(start = 8.dp)
                )
            }
        }
        
        if (scenario.expectedOutcome.notes.isNotEmpty()) {
            Spacer(Modifier.height(8.dp))
            Card(
                colors = CardDefaults.cardColors(
                    containerColor = MaterialTheme.colorScheme.secondaryContainer.copy(alpha = 0.5f)
                )
            ) {
                Row(
                    modifier = Modifier.padding(12.dp),
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    Icon(
                        Icons.Filled.Info,
                        contentDescription = null,
                        tint = MaterialTheme.colorScheme.onSecondaryContainer
                    )
                    Text(
                        scenario.expectedOutcome.notes,
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSecondaryContainer
                    )
                }
            }
        }
    }
}

@Composable
fun DetailRow(
    label: String,
    value: String,
    valueColor: androidx.compose.ui.graphics.Color = MaterialTheme.colorScheme.onSurface
) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.SpaceBetween
    ) {
        Text(
            text = "$label:",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
        Text(
            text = value,
            style = MaterialTheme.typography.bodySmall,
            fontWeight = FontWeight.Medium,
            color = valueColor
        )
    }
}
