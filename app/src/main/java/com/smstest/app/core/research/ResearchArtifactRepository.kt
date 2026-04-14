package com.smstest.app.core.research

enum class ArtifactSource {
    PHASE_DOC,
    SCRIPT,
    BINARY,
    TOOL_OUTPUT
}

enum class ArtifactPriority {
    HIGH,
    MEDIUM,
    LOW
}

data class ResearchArtifact(
    val id: String,
    val title: String,
    val summary: String,
    val source: ArtifactSource,
    val path: String,
    val priority: ArtifactPriority,
    val tags: List<String> = emptyList()
)

object ResearchArtifactRepository {
    fun getArtifacts(): List<ResearchArtifact> = listOf(
        ResearchArtifact(
            id = "phase5-status",
            title = "Phase 5 Session Status",
            summary = "Current research progress, blockers, and next tasks for MiFi extraction and analysis.",
            source = ArtifactSource.PHASE_DOC,
            path = "PHASE_5_SESSION_STATUS.md",
            priority = ArtifactPriority.HIGH,
            tags = listOf("phase", "status", "planning")
        ),
        ResearchArtifact(
            id = "phase5-startup",
            title = "Phase 5 Startup Checklist",
            summary = "Operator checklist used to resume sessions safely with device and tooling prerequisites.",
            source = ArtifactSource.PHASE_DOC,
            path = "PHASE_5_STARTUP_CHECKLIST.md",
            priority = ArtifactPriority.HIGH,
            tags = listOf("phase", "checklist")
        ),
        ResearchArtifact(
            id = "cli-entrypoint",
            title = "Desktop Modem CLI",
            summary = "Primary adb-based workflow for probing modem nodes, enabling diag mode, and sending tests.",
            source = ArtifactSource.SCRIPT,
            path = "tools/smstest_cli.py",
            priority = ArtifactPriority.HIGH,
            tags = listOf("cli", "adb", "probe", "diag")
        ),
        ResearchArtifact(
            id = "gp-ghidra-script",
            title = "GlobalPlatformPro Ghidra Analyzer",
            summary = "Script for triaging gp.jar SCP-related symbols and candidate key derivation routines.",
            source = ArtifactSource.SCRIPT,
            path = "tools/ghidra_gp_analyzer.py",
            priority = ArtifactPriority.MEDIUM,
            tags = listOf("ghidra", "gp", "scp")
        ),
        ResearchArtifact(
            id = "libmodem2",
            title = "libmodem2_api.so",
            summary = "Primary modem library targeted for SPC and command path reverse engineering.",
            source = ArtifactSource.BINARY,
            path = "mifi_backup/binaries/libmodem2_api.so",
            priority = ArtifactPriority.HIGH,
            tags = listOf("binary", "modem", "spc")
        ),
        ResearchArtifact(
            id = "libmal-qct",
            title = "libmal_qct.so",
            summary = "QMI-related library containing carrier and NV operation logic paths.",
            source = ArtifactSource.BINARY,
            path = "mifi_backup/binaries/libmal_qct.so",
            priority = ArtifactPriority.MEDIUM,
            tags = listOf("binary", "qmi", "nv")
        ),
        ResearchArtifact(
            id = "modem2-cli",
            title = "modem2_cli",
            summary = "Extracted CLI entrypoint binary for modem command surface analysis.",
            source = ArtifactSource.BINARY,
            path = "mifi_backup/binaries/modem2_cli",
            priority = ArtifactPriority.MEDIUM,
            tags = listOf("binary", "cli")
        ),
        ResearchArtifact(
            id = "analysis-results",
            title = "Binary Analysis Results",
            summary = "Structured output from automated binary analysis runs used for quick diffing.",
            source = ArtifactSource.TOOL_OUTPUT,
            path = "analysis/binary_analysis_results.json",
            priority = ArtifactPriority.LOW,
            tags = listOf("analysis", "json")
        )
    )
}

