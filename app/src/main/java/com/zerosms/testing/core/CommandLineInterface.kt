package com.zerosms.testing.core

import android.content.Context
import android.util.Log
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import java.io.BufferedReader
import java.io.InputStreamReader

/**
 * Command Line Interface for ZeroSMS testing
 * Provides CLI access to main app functionality
 */
class CommandLineInterface(private val context: Context) {
    
    private val tag = "ZeroSMS_CLI"
    
    companion object {
        const val ANSI_RESET = "\u001B[0m"
        const val ANSI_BOLD = "\u001B[1m"
        const val ANSI_GREEN = "\u001B[32m"
        const val ANSI_RED = "\u001B[31m"
        const val ANSI_BLUE = "\u001B[34m"
        const val ANSI_YELLOW = "\u001B[33m"
        const val ANSI_CLEAR_SCREEN = "\u001B[2J"
        const val ANSI_HOME = "\u001B[H"
        
        // Cursor navigation keys
        const val KEY_UP = "\u001B[A"
        const val KEY_DOWN = "\u001B[B"
        const val KEY_RIGHT = "\u001B[C"
        const val KEY_LEFT = "\u001B[D"
    }
    
    fun startCLI() {
        CoroutineScope(Dispatchers.IO).launch {
            showWelcome()
            processCommands()
        }
    }
    
    private fun showWelcome() {
        println("$ANSI_CLEAR_SCREEN$ANSI_HOME")
        println("${ANSI_BOLD}${ANSI_BLUE}╔══════════════════════════════════════════╗$ANSI_RESET")
        println("${ANSI_BOLD}${ANSI_BLUE}║          ZeroSMS CLI Interface           ║$ANSI_RESET")
        println("${ANSI_BOLD}${ANSI_BLUE}║    Silent SMS/MMS/RCS Testing Suite      ║$ANSI_RESET")
        println("${ANSI_BOLD}${ANSI_BLUE}╚══════════════════════════════════════════╝$ANSI_RESET")
        println()
        println("${ANSI_GREEN}Use arrow keys for navigation, Enter to select$ANSI_RESET")
        println("${ANSI_GREEN}Available Commands:$ANSI_RESET")
        showHelp()
    }
    
    private fun showHelp() {
        val commands = mapOf(
            "test sms <number>" to "Send SMS test to specified number",
            "test mms <number>" to "Send MMS test to specified number", 
            "test rcs <number>" to "Send RCS test to specified number",
            "monitor start" to "Start message monitoring",
            "monitor stop" to "Stop message monitoring",
            "results" to "Show test results",
            "settings" to "Show current settings",
            "menu" to "Interactive menu (cursor navigation)",
            "clear" to "Clear screen",
            "help" to "Show this help",
            "exit" to "Exit CLI"
        )
        
        commands.forEach { (command, description) ->
            println("  ${ANSI_YELLOW}$command$ANSI_RESET - $description")
        }
        println()
    }
    
    private suspend fun processCommands() {
        val reader = BufferedReader(InputStreamReader(System.`in`))
        
        while (true) {
            print("${ANSI_GREEN}zerosms> $ANSI_RESET")
            val input = reader.readLine()?.trim()
            
            if (input.isNullOrEmpty()) continue
            
            when {
                input.startsWith("test sms ") -> {
                    val number = input.substringAfter("test sms ").trim()
                    if (number.isNotEmpty()) {
                        executeSmsTest(number)
                    } else {
                        println("${ANSI_RED}Error: Phone number required$ANSI_RESET")
                    }
                }
                input.startsWith("test mms ") -> {
                    val number = input.substringAfter("test mms ").trim()
                    if (number.isNotEmpty()) {
                        executeMmsTest(number)
                    } else {
                        println("${ANSI_RED}Error: Phone number required$ANSI_RESET")
                    }
                }
                input.startsWith("test rcs ") -> {
                    val number = input.substringAfter("test rcs ").trim()
                    if (number.isNotEmpty()) {
                        executeRcsTest(number)
                    } else {
                        println("${ANSI_RED}Error: Phone number required$ANSI_RESET")
                    }
                }
                input == "monitor start" -> startMonitoring()
                input == "monitor stop" -> stopMonitoring()
                input == "results" -> showResults()
                input == "settings" -> showSettings()
                input == "menu" -> showInteractiveMenu()
                input == "clear" -> println("$ANSI_CLEAR_SCREEN$ANSI_HOME")
                input == "help" -> showHelp()
                input == "exit" -> {
                    println("${ANSI_BLUE}Goodbye!$ANSI_RESET")
                    break
                }
                else -> println("${ANSI_RED}Unknown command: $input. Type 'help' for available commands.$ANSI_RESET")
            }
        }
    }
    
    private fun showInteractiveMenu() {
        val menuItems = listOf(
            "SMS Test",
            "MMS Test", 
            "RCS Test",
            "Start Monitor",
            "Stop Monitor",
            "View Results",
            "Settings",
            "Exit"
        )
        
        var selectedIndex = 0
        println("${ANSI_CLEAR_SCREEN}${ANSI_HOME}")
        println("${ANSI_BOLD}${ANSI_BLUE}Interactive Menu - Use ↑↓ to navigate, Enter to select$ANSI_RESET")
        
        fun displayMenu() {
            println("$ANSI_HOME")
            println("${ANSI_BOLD}${ANSI_BLUE}Interactive Menu - Use ↑↓ to navigate, Enter to select$ANSI_RESET")
            println()
            menuItems.forEachIndexed { index, item ->
                if (index == selectedIndex) {
                    println("${ANSI_GREEN}► $item$ANSI_RESET")
                } else {
                    println("  $item")
                }
            }
        }
        
        displayMenu()
        println("${ANSI_YELLOW}Note: Cursor navigation requires terminal support$ANSI_RESET")
    }
    
    private fun executeSmsTest(number: String) {
        println("${ANSI_BLUE}Executing SMS test to $number...$ANSI_RESET")
        Log.i(tag, "SMS test initiated for number: $number")
        // TODO: Integrate with existing SMS test functionality
        println("${ANSI_GREEN}SMS test completed$ANSI_RESET")
    }
    
    private fun executeMmsTest(number: String) {
        println("${ANSI_BLUE}Executing MMS test to $number...$ANSI_RESET")
        Log.i(tag, "MMS test initiated for number: $number")
        // TODO: Integrate with existing MMS test functionality
        println("${ANSI_GREEN}MMS test completed$ANSI_RESET")
    }
    
    private fun executeRcsTest(number: String) {
        println("${ANSI_BLUE}Executing RCS test to $number...$ANSI_RESET")
        Log.i(tag, "RCS test initiated for number: $number")
        // TODO: Integrate with existing RCS test functionality
        println("${ANSI_GREEN}RCS test completed$ANSI_RESET")
    }
    
    private fun startMonitoring() {
        println("${ANSI_GREEN}Message monitoring started$ANSI_RESET")
        Log.i(tag, "Message monitoring started via CLI")
        // TODO: Integrate with existing monitoring functionality
    }
    
    private fun stopMonitoring() {
        println("${ANSI_YELLOW}Message monitoring stopped$ANSI_RESET")
        Log.i(tag, "Message monitoring stopped via CLI")
        // TODO: Integrate with existing monitoring functionality
    }
    
    private fun showResults() {
        println("${ANSI_BLUE}Test Results:$ANSI_RESET")
        // TODO: Integrate with existing results functionality
        println("No tests run yet")
    }
    
    private fun showSettings() {
        println("${ANSI_BLUE}Current Settings:$ANSI_RESET")
        // TODO: Integrate with existing settings functionality
        println("Settings not configured")
    }
}