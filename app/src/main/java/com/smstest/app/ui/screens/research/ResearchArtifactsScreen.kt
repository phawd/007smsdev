package com.smstest.app.ui.screens.research

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ArrowBack
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilterChip
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.smstest.app.core.research.ArtifactPriority
import com.smstest.app.core.research.ArtifactSource
import com.smstest.app.core.research.ResearchArtifact
import com.smstest.app.core.research.ResearchArtifactRepository

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ResearchArtifactsScreen(
    onNavigateBack: () -> Unit
) {
    val artifacts = remember { ResearchArtifactRepository.getArtifacts() }
    var selectedSource by remember { mutableStateOf<ArtifactSource?>(null) }

    val filteredArtifacts = remember(artifacts, selectedSource) {
        artifacts.filter { selectedSource == null || it.source == selectedSource }
            .sortedByDescending { it.priority }
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Research Artifacts") },
                navigationIcon = {
                    IconButton(onClick = onNavigateBack) {
                        Icon(Icons.Filled.ArrowBack, contentDescription = "Back")
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
            Text(
                text = "Curated findings from phase docs, tooling scripts, and extracted binaries.",
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
            Spacer(Modifier.height(12.dp))

            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                FilterChip(
                    selected = selectedSource == null,
                    onClick = { selectedSource = null },
                    label = { Text("All") }
                )
                ArtifactSource.entries.forEach { source ->
                    FilterChip(
                        selected = selectedSource == source,
                        onClick = { selectedSource = source },
                        label = { Text(source.name.replace('_', ' ')) }
                    )
                }
            }

            Spacer(Modifier.height(12.dp))
            HorizontalDivider()
            Spacer(Modifier.height(12.dp))

            LazyColumn(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                items(filteredArtifacts, key = { it.id }) { artifact ->
                    ArtifactCard(artifact = artifact)
                }
            }
        }
    }
}

@Composable
private fun ArtifactCard(artifact: ResearchArtifact) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant)
    ) {
        Column(
            modifier = Modifier.padding(14.dp),
            verticalArrangement = Arrangement.spacedBy(6.dp)
        ) {
            Text(
                text = artifact.title,
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.SemiBold
            )
            Text(
                text = artifact.summary,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
            Text(
                text = "Path: ${artifact.path}",
                style = MaterialTheme.typography.bodySmall,
                fontWeight = FontWeight.Medium
            )
            Text(
                text = "Source: ${artifact.source.name} | Priority: ${artifact.priority.name}",
                style = MaterialTheme.typography.labelSmall,
                color = priorityColor(artifact.priority)
            )
            if (artifact.tags.isNotEmpty()) {
                Text(
                    text = artifact.tags.joinToString(prefix = "Tags: ", separator = ", "),
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        }
    }
}

@Composable
private fun priorityColor(priority: ArtifactPriority): Color = when (priority) {
    ArtifactPriority.HIGH -> MaterialTheme.colorScheme.error
    ArtifactPriority.MEDIUM -> MaterialTheme.colorScheme.primary
    ArtifactPriority.LOW -> MaterialTheme.colorScheme.tertiary
}

