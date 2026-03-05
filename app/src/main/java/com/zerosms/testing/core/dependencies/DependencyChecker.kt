package com.zerosms.testing.core.dependencies

import android.Manifest
import android.content.Context
import android.content.pm.PackageManager
import androidx.core.content.ContextCompat
import com.zerosms.testing.BuildConfig

data class DependencyIssue(
    val id: String,
    val title: String,
    val description: String,
    val action: DependencyAction
)

sealed class DependencyAction {
    data class OpenUrl(val label: String, val url: String) : DependencyAction()
    data class OpenAppSettings(val label: String) : DependencyAction()
    data class None(val label: String) : DependencyAction()
}

object DependencyChecker {
    fun collect(context: Context, rootAvailable: Boolean?, atReady: Boolean?): List<DependencyIssue> {
        val issues = mutableListOf<DependencyIssue>()

        if (BuildConfig.APIFY_API_KEY == "REPLACE_ME") {
            issues += DependencyIssue(
                id = "apify-key",
                title = "Apify API key not configured",
                description = "Set APIFY_API_KEY in your Gradle properties or environment to unlock Apify-backed features.",
                action = DependencyAction.OpenUrl(
                    label = "Apify docs",
                    url = "https://docs.apify.com/"
                )
            )
        }

        val missingPermissions = REQUIRED_PERMISSIONS.filterNot { permission ->
            ContextCompat.checkSelfPermission(context, permission) == PackageManager.PERMISSION_GRANTED
        }
        if (missingPermissions.isNotEmpty()) {
            val readable = missingPermissions.joinToString()
            issues += DependencyIssue(
                id = "runtime-permissions",
                title = "Runtime permissions missing",
                description = "Grant required permissions to send and monitor messages: $readable",
                action = DependencyAction.OpenAppSettings(label = "Open app settings")
            )
        }

        if (rootAvailable == false) {
            issues += DependencyIssue(
                id = "root-access",
                title = "Root access unavailable",
                description = "AT command and diag-port workflows require root. Standard API SMS is still available.",
                action = DependencyAction.None(label = "Requires rooted device")
            )
        } else if (rootAvailable == true && atReady == false) {
            issues += DependencyIssue(
                id = "at-init",
                title = "AT command interface not initialized",
                description = "Root is available, but AT command initialization failed. Check modem paths and permissions.",
                action = DependencyAction.None(label = "Check modem access")
            )
        }

        return issues
    }

    private val REQUIRED_PERMISSIONS = listOf(
        Manifest.permission.SEND_SMS,
        Manifest.permission.RECEIVE_SMS,
        Manifest.permission.READ_SMS,
        Manifest.permission.READ_PHONE_STATE,
        Manifest.permission.RECEIVE_MMS
    )
}
