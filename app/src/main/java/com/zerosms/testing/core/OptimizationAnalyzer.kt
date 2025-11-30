package com.zerosms.testing.core

import android.content.Context
import android.util.Log
import java.io.File

/**
 * Optimization analyzer for ZeroSMS codebase
 * Recursively searches for optimization opportunities
 */
class OptimizationAnalyzer(private val context: Context) {
    
    private val tag = "OptimizationAnalyzer"
    
    data class OptimizationSuggestion(
        val file: String,
        val line: Int,
        val type: OptimizationType,
        val description: String,
        val suggestion: String
    )
    
    enum class OptimizationType {
        PERFORMANCE,
        MEMORY,
        CODE_QUALITY,
        SECURITY,
        MAINTAINABILITY
    }
    
    fun analyzeCodebase(rootPath: String): List<OptimizationSuggestion> {
        val suggestions = mutableListOf<OptimizationSuggestion>()
        val rootDir = File(rootPath)
        
        if (rootDir.exists() && rootDir.isDirectory) {
            analyzeDirectory(rootDir, suggestions)
        }
        
        Log.i(tag, "Found ${suggestions.size} optimization opportunities")
        return suggestions
    }
    
    private fun analyzeDirectory(directory: File, suggestions: MutableList<OptimizationSuggestion>) {
        directory.listFiles()?.forEach { file ->
            when {
                file.isDirectory -> analyzeDirectory(file, suggestions)
                file.extension == "kt" -> analyzeKotlinFile(file, suggestions)
                file.extension == "gradle" || file.name.endsWith(".gradle.kts") -> 
                    analyzeGradleFile(file, suggestions)
                file.name == "AndroidManifest.xml" -> analyzeManifestFile(file, suggestions)
            }
        }
    }
    
    private fun analyzeKotlinFile(file: File, suggestions: MutableList<OptimizationSuggestion>) {
        try {
            val lines = file.readLines()
            lines.forEachIndexed { index, line ->
                val lineNumber = index + 1
                
                // Performance optimizations
                if (line.contains("findViewById")) {
                    suggestions.add(OptimizationSuggestion(
                        file = file.absolutePath,
                        line = lineNumber,
                        type = OptimizationType.PERFORMANCE,
                        description = "Using findViewById - can be slow",
                        suggestion = "Consider using View Binding or Compose"
                    ))
                }
                
                if (line.contains("GlobalScope.launch")) {
                    suggestions.add(OptimizationSuggestion(
                        file = file.absolutePath,
                        line = lineNumber,
                        type = OptimizationType.PERFORMANCE,
                        description = "Using GlobalScope can cause memory leaks",
                        suggestion = "Use viewModelScope or lifecycleScope instead"
                    ))
                }
                
                // Memory optimizations
                if (line.contains("ArrayList()") && !line.contains("mutableListOf")) {
                    suggestions.add(OptimizationSuggestion(
                        file = file.absolutePath,
                        line = lineNumber,
                        type = OptimizationType.MEMORY,
                        description = "Raw ArrayList usage",
                        suggestion = "Use mutableListOf() for better Kotlin integration"
                    ))
                }
                
                // Code quality improvements
                if (line.contains("!!")) {
                    suggestions.add(OptimizationSuggestion(
                        file = file.absolutePath,
                        line = lineNumber,
                        type = OptimizationType.CODE_QUALITY,
                        description = "Force unwrapping with !! can cause crashes",
                        suggestion = "Use safe calls (?.) or proper null checking"
                    ))
                }
                
                if (line.trim().startsWith("// TODO")) {
                    suggestions.add(OptimizationSuggestion(
                        file = file.absolutePath,
                        line = lineNumber,
                        type = OptimizationType.MAINTAINABILITY,
                        description = "TODO comment found",
                        suggestion = "Implement or remove TODO comments"
                    ))
                }
                
                // Security improvements
                if (line.contains("Log.d") || line.contains("Log.v")) {
                    suggestions.add(OptimizationSuggestion(
                        file = file.absolutePath,
                        line = lineNumber,
                        type = OptimizationType.SECURITY,
                        description = "Debug/verbose logging in production code",
                        suggestion = "Use conditional logging or remove for production"
                    ))
                }
                
                // Performance: String concatenation in loops
                if (line.contains("+") && line.contains("\"") && 
                    (lines.getOrNull(index - 1)?.contains("for") == true ||
                     lines.getOrNull(index - 1)?.contains("while") == true)) {
                    suggestions.add(OptimizationSuggestion(
                        file = file.absolutePath,
                        line = lineNumber,
                        type = OptimizationType.PERFORMANCE,
                        description = "String concatenation in loop",
                        suggestion = "Use StringBuilder or string templates"
                    ))
                }
            }
        } catch (e: Exception) {
            Log.w(tag, "Error analyzing file ${file.absolutePath}: ${e.message}")
        }
    }
    
    private fun analyzeGradleFile(file: File, suggestions: MutableList<OptimizationSuggestion>) {
        try {
            val lines = file.readLines()
            lines.forEachIndexed { index, line ->
                val lineNumber = index + 1
                
                // Dependency optimizations
                if (line.contains("implementation") && line.contains(":+")) {
                    suggestions.add(OptimizationSuggestion(
                        file = file.absolutePath,
                        line = lineNumber,
                        type = OptimizationType.MAINTAINABILITY,
                        description = "Dynamic version (+) in dependency",
                        suggestion = "Use specific version numbers for reproducible builds"
                    ))
                }
                
                // Build performance
                if (line.contains("minifyEnabled = false") && file.name.contains("build.gradle")) {
                    suggestions.add(OptimizationSuggestion(
                        file = file.absolutePath,
                        line = lineNumber,
                        type = OptimizationType.PERFORMANCE,
                        description = "Minification disabled for release builds",
                        suggestion = "Enable minification for smaller APK size"
                    ))
                }
            }
        } catch (e: Exception) {
            Log.w(tag, "Error analyzing gradle file ${file.absolutePath}: ${e.message}")
        }
    }
    
    private fun analyzeManifestFile(file: File, suggestions: MutableList<OptimizationSuggestion>) {
        try {
            val content = file.readText()
            
            if (!content.contains("android:allowBackup=\"false\"")) {
                suggestions.add(OptimizationSuggestion(
                    file = file.absolutePath,
                    line = 1,
                    type = OptimizationType.SECURITY,
                    description = "App backup not disabled",
                    suggestion = "Add android:allowBackup=\"false\" for security"
                ))
            }
            
            if (content.contains("android:exported=\"true\"")) {
                suggestions.add(OptimizationSuggestion(
                    file = file.absolutePath,
                    line = 1,
                    type = OptimizationType.SECURITY,
                    description = "Components exported without proper filtering",
                    suggestion = "Review exported components and add intent filters"
                ))
            }
        } catch (e: Exception) {
            Log.w(tag, "Error analyzing manifest file ${file.absolutePath}: ${e.message}")
        }
    }
    
    fun generateOptimizationReport(suggestions: List<OptimizationSuggestion>): String {
        val report = StringBuilder()
        report.appendLine("=== ZeroSMS Codebase Optimization Report ===\n")
        
        val groupedSuggestions = suggestions.groupBy { it.type }
        
        groupedSuggestions.forEach { (type, typeSuggestions) ->
            report.appendLine("${type.name} (${typeSuggestions.size} items):")
            report.appendLine("-".repeat(40))
            
            typeSuggestions.forEach { suggestion ->
                report.appendLine("File: ${suggestion.file}")
                report.appendLine("Line: ${suggestion.line}")
                report.appendLine("Issue: ${suggestion.description}")
                report.appendLine("Suggestion: ${suggestion.suggestion}")
                report.appendLine()
            }
        }
        
        report.appendLine("Total suggestions: ${suggestions.size}")
        return report.toString()
    }
}