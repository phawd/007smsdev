package com.smstest.app

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.ui.Modifier
import com.smstest.app.ui.navigation.AppNavigation
import com.smstest.app.ui.theme.AppTheme
import com.smstest.app.core.CommandLineInterface

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        
        // Check if CLI mode is requested
        val cliMode = intent?.getStringExtra("cli") == "true"
        if (cliMode) {
            val cli = CommandLineInterface(this)
            cli.startCLI()
            return
        }
        
        setContent {
            AppTheme {
                Surface(
                    modifier = Modifier.fillMaxSize(),
                    color = MaterialTheme.colorScheme.background
                ) {
                    AppNavigation()
                }
            }
        }
    }
}
