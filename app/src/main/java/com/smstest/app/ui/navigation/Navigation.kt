package com.smstest.app.ui.navigation

import androidx.compose.runtime.Composable
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.rememberNavController
import com.smstest.app.ui.screens.home.HomeScreen
import com.smstest.app.ui.screens.test.TestScreen
import com.smstest.app.ui.screens.results.ResultsScreen
import com.smstest.app.ui.screens.settings.SettingsScreen
import com.smstest.app.ui.screens.monitor.MonitorScreen

sealed class Screen(val route: String) {
    object Home : Screen("home")
    object Test : Screen("test/{messageType}") {
        fun createRoute(messageType: String) = "test/$messageType"
    }
    object Results : Screen("results")
    object Settings : Screen("settings")
    object Monitor : Screen("monitor")
}

@Composable
fun AppNavigation() {
    val navController = rememberNavController()
    
    NavHost(
        navController = navController,
        startDestination = Screen.Home.route
    ) {
        composable(Screen.Home.route) {
            HomeScreen(
                onNavigateToTest = { messageType ->
                    navController.navigate(Screen.Test.createRoute(messageType))
                },
                onNavigateToResults = {
                    navController.navigate(Screen.Results.route)
                },
                onNavigateToSettings = {
                    navController.navigate(Screen.Settings.route)
                },
                onNavigateToMonitor = {
                    navController.navigate(Screen.Monitor.route)
                }
            )
        }
        
        composable(Screen.Test.route) { backStackEntry ->
            val messageType = backStackEntry.arguments?.getString("messageType") ?: "SMS"
            TestScreen(
                messageType = messageType,
                onNavigateBack = { navController.popBackStack() }
            )
        }
        
        composable(Screen.Results.route) {
            ResultsScreen(
                onNavigateBack = { navController.popBackStack() }
            )
        }
        
        composable(Screen.Settings.route) {
            SettingsScreen(
                onNavigateBack = { navController.popBackStack() }
            )
        }
        
        composable(Screen.Monitor.route) {
            MonitorScreen(
                onNavigateBack = { navController.popBackStack() }
            )
        }
    }
}
