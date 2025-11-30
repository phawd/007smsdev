package com.zerosms.testing.core.settings

import android.content.Context
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.stringPreferencesKey
import androidx.datastore.preferences.core.booleanPreferencesKey
import androidx.datastore.preferences.core.intPreferencesKey
import androidx.datastore.preferences.preferencesDataStore
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.map

private val Context.dataStore by preferencesDataStore(name = "zerosms_settings")

object SettingsRepository {
    private val FLASH_DEST_NUMBER = stringPreferencesKey("flash_destination_number")
    private val AUTO_DELIVERY = booleanPreferencesKey("auto_delivery_report")
    private val AUTO_READ = booleanPreferencesKey("auto_read_report")
    private val DEFAULT_ENCODING = stringPreferencesKey("default_encoding")
    private val LOG_LEVEL = stringPreferencesKey("log_level")
    private val MMSC_URL = stringPreferencesKey("mmsc_url")
    private val MMSC_PROXY = stringPreferencesKey("mmsc_proxy")
    private val MMSC_PORT = stringPreferencesKey("mmsc_port")
    private val AT_INITIALIZED = booleanPreferencesKey("at_initialized")
    private val LAST_MODEM_DEVICE = stringPreferencesKey("last_modem_device")

    fun flashDestinationFlow(context: Context): Flow<String> =
        context.dataStore.data.map { prefs -> prefs[FLASH_DEST_NUMBER] ?: "" }

    fun autoDeliveryFlow(context: Context): Flow<Boolean> =
        context.dataStore.data.map { prefs -> prefs[AUTO_DELIVERY] ?: true }

    fun autoReadFlow(context: Context): Flow<Boolean> =
        context.dataStore.data.map { prefs -> prefs[AUTO_READ] ?: false }

    fun defaultEncodingFlow(context: Context): Flow<String> =
        context.dataStore.data.map { prefs -> prefs[DEFAULT_ENCODING] ?: "AUTO" }

    fun logLevelFlow(context: Context): Flow<String> =
        context.dataStore.data.map { prefs -> prefs[LOG_LEVEL] ?: "INFO" }

    fun mmscUrlFlow(context: Context): Flow<String> =
        context.dataStore.data.map { prefs -> prefs[MMSC_URL] ?: "" }

    fun mmscProxyFlow(context: Context): Flow<String> =
        context.dataStore.data.map { prefs -> prefs[MMSC_PROXY] ?: "" }

    fun mmscPortFlow(context: Context): Flow<String> =
        context.dataStore.data.map { prefs -> prefs[MMSC_PORT] ?: "80" }

    fun atInitializedFlow(context: Context): Flow<Boolean> =
        context.dataStore.data.map { prefs -> prefs[AT_INITIALIZED] ?: false }

    fun lastModemDeviceFlow(context: Context): Flow<String> =
        context.dataStore.data.map { prefs -> prefs[LAST_MODEM_DEVICE] ?: "" }

    suspend fun setFlashDestination(context: Context, number: String) {
        context.dataStore.edit { prefs ->
            prefs[FLASH_DEST_NUMBER] = number.trim()
        }
    }

    suspend fun setAutoDelivery(context: Context, enabled: Boolean) {
        context.dataStore.edit { prefs -> prefs[AUTO_DELIVERY] = enabled }
    }

    suspend fun setAutoRead(context: Context, enabled: Boolean) {
        context.dataStore.edit { prefs -> prefs[AUTO_READ] = enabled }
    }

    suspend fun setDefaultEncoding(context: Context, encoding: String) {
        context.dataStore.edit { prefs -> prefs[DEFAULT_ENCODING] = encoding }
    }

    suspend fun setLogLevel(context: Context, level: String) {
        context.dataStore.edit { prefs -> prefs[LOG_LEVEL] = level }
    }

    suspend fun setMmscConfig(context: Context, url: String, proxy: String, port: String) {
        context.dataStore.edit { prefs ->
            prefs[MMSC_URL] = url.trim()
            prefs[MMSC_PROXY] = proxy.trim()
            prefs[MMSC_PORT] = port.trim()
        }
    }

    suspend fun setAtInitialized(context: Context, initialized: Boolean) {
        context.dataStore.edit { prefs -> prefs[AT_INITIALIZED] = initialized }
    }

    suspend fun setLastModemDevice(context: Context, device: String) {
        context.dataStore.edit { prefs -> prefs[LAST_MODEM_DEVICE] = device }
    }
}
