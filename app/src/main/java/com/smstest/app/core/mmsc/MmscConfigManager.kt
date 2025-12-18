package com.smstest.app.core.mmsc

import android.content.Context
import android.util.Log
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * MMSC (MMS Service Center) Configuration Manager
 * 
 * Manages MMS gateway configuration for sending MMS via MMSC.
 * Different carriers use different MMSC settings.
 */
class MmscConfigManager(private val context: Context) {
    
    private val TAG = "MmscConfigManager"
    
    /**
     * Get current MMSC configuration
     * Attempts to read from APN settings
     */
    suspend fun getCurrentMmscConfig(): MmscConfig? = withContext(Dispatchers.IO) {
        try {
            // Try to read from system APN settings
            // Note: Requires READ_APN_SETTINGS permission (system app only)
            // For non-system apps, use stored configuration
            getStoredMmscConfig()
        } catch (e: Exception) {
            Log.e(TAG, "Failed to get MMSC config", e)
            null
        }
    }
    
    /**
     * Save MMSC configuration
     */
    suspend fun saveMmscConfig(config: MmscConfig) = withContext(Dispatchers.IO) {
        try {
            val prefs = context.getSharedPreferences("mmsc_config", Context.MODE_PRIVATE)
            prefs.edit().apply {
                putString("mmsc_url", config.mmscUrl)
                putString("mmsc_proxy", config.mmscProxy)
                putInt("mmsc_port", config.mmscPort)
                putString("carrier", config.carrier)
                apply()
            }
            Log.d(TAG, "MMSC config saved: $config")
        } catch (e: Exception) {
            Log.e(TAG, "Failed to save MMSC config", e)
        }
    }
    
    /**
     * Get stored MMSC configuration
     */
    private fun getStoredMmscConfig(): MmscConfig? {
        val prefs = context.getSharedPreferences("mmsc_config", Context.MODE_PRIVATE)
        val mmscUrl = prefs.getString("mmsc_url", null) ?: return null
        
        return MmscConfig(
            mmscUrl = mmscUrl,
            mmscProxy = prefs.getString("mmsc_proxy", ""),
            mmscPort = prefs.getInt("mmsc_port", 80),
            carrier = prefs.getString("carrier", "Custom")
        )
    }
    
    /**
     * Get predefined carrier configurations
     */
    fun getCarrierPresets(): List<MmscConfig> {
        return listOf(
            // T-Mobile USA
            MmscConfig(
                mmscUrl = "http://mms.msg.eng.t-mobile.com/mms/wapenc",
                mmscProxy = "",
                mmscPort = 80,
                carrier = "T-Mobile USA"
            ),
            
            // AT&T USA
            MmscConfig(
                mmscUrl = "http://mmsc.mobile.att.net",
                mmscProxy = "proxy.mobile.att.net",
                mmscPort = 80,
                carrier = "AT&T USA"
            ),
            
            // Verizon USA
            MmscConfig(
                mmscUrl = "http://mms.vtext.com/servlets/mms",
                mmscProxy = "",
                mmscPort = 80,
                carrier = "Verizon USA"
            ),
            
            // Sprint USA
            MmscConfig(
                mmscUrl = "http://mms.sprintpcs.com",
                mmscProxy = "",
                mmscPort = 80,
                carrier = "Sprint USA"
            ),
            
            // Vodafone UK
            MmscConfig(
                mmscUrl = "http://mms.vodafone.co.uk/servlets/mms",
                mmscProxy = "212.183.137.12",
                mmscPort = 8799,
                carrier = "Vodafone UK"
            ),
            
            // O2 UK
            MmscConfig(
                mmscUrl = "http://mmsc.mms.o2.co.uk:8002",
                mmscProxy = "193.113.200.195",
                mmscPort = 8080,
                carrier = "O2 UK"
            ),
            
            // Orange France
            MmscConfig(
                mmscUrl = "http://mms.orange.fr",
                mmscProxy = "192.168.10.200",
                mmscPort = 8080,
                carrier = "Orange France"
            ),
            
            // Deutsche Telekom Germany
            MmscConfig(
                mmscUrl = "http://mms.t-mobile.de/servlets/mms",
                mmscProxy = "172.28.23.131",
                mmscPort = 8008,
                carrier = "T-Mobile Germany"
            )
        )
    }
    
    /**
     * Detect carrier from device
     */
    suspend fun detectCarrier(): String? = withContext(Dispatchers.IO) {
        try {
            val telephonyManager = context.getSystemService(Context.TELEPHONY_SERVICE) 
                as? android.telephony.TelephonyManager
            
            telephonyManager?.networkOperatorName
        } catch (e: Exception) {
            Log.e(TAG, "Failed to detect carrier", e)
            null
        }
    }
}

/**
 * MMSC Configuration data
 */
data class MmscConfig(
    val mmscUrl: String,
    val mmscProxy: String? = null,
    val mmscPort: Int = 80,
    val carrier: String? = null
)
