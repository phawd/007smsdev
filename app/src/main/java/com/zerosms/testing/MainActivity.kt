package com.zerosms.testing

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.ui.Modifier
import com.zerosms.testing.ui.navigation.ZeroSMSNavigation
import com.zerosms.testing.ui.theme.ZeroSMSTheme
import com.zerosms.testing.core.CommandLineInterface

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
            ZeroSMSTheme {
                Surface(
                    modifier = Modifier.fillMaxSize(),
                    color = MaterialTheme.colorScheme.background
                ) {
                    ZeroSMSNavigation()
                }
            }
        }
    }
}
