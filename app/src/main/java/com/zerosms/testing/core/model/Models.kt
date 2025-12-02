package com.zerosms.testing.core.model

import java.util.Date

/**
 * Message types supported by ZeroSMS
 */
enum class MessageType {
    SMS_TEXT,           // Standard SMS text message (GSM 03.40)
    SMS_BINARY,         // Binary SMS (for data)
    SMS_FLASH,          // Class 0 SMS (Flash SMS)
    SMS_SILENT,         // Silent SMS (Type 0)
    MMS_TEXT,           // MMS with text only
    MMS_IMAGE,          // MMS with image attachment
    MMS_VIDEO,          // MMS with video attachment
    MMS_AUDIO,          // MMS with audio attachment
    MMS_VCARD,          // MMS with vCard
    MMS_MIXED,          // MMS with multiple media types
    RCS_TEXT,           // RCS text message
    RCS_FILE_TRANSFER,  // RCS file transfer
    RCS_GROUP_CHAT      // RCS group chat
}

/**
 * SMS encoding types per GSM 03.38
 */
enum class SmsEncoding {
    GSM_7BIT,           // GSM 7-bit default alphabet
    GSM_8BIT,           // 8-bit data encoding
    UCS2,               // UCS-2 (16-bit Unicode)
    AUTO                // Automatic selection
}

/**
 * Message class per 3GPP TS 23.038
 */
enum class MessageClass {
    CLASS_0,            // Flash message (immediate display)
    CLASS_1,            // ME-specific (mobile equipment)
    CLASS_2,            // SIM-specific
    CLASS_3,            // TE-specific (terminal equipment)
    NONE                // No class specified
}

/**
 * Message priority levels
 */
enum class Priority {
    LOW,
    NORMAL,
    HIGH,
    URGENT
}

/**
 * Delivery status per GSM 03.40
 */
enum class DeliveryStatus {
    PENDING,
    SENT,
    DELIVERED,
    FAILED,
    EXPIRED,
    REJECTED,
    UNDELIVERABLE
}

/**
 * Core message data model
 */
data class Message(
    val id: String,
    val type: MessageType,
    val destination: String,
    val body: String? = null,
    val subject: String? = null,
    val timestamp: Date = Date(),
    val encoding: SmsEncoding = SmsEncoding.AUTO,
    val messageClass: MessageClass = MessageClass.NONE,
    val priority: Priority = Priority.NORMAL,
    val deliveryReport: Boolean = false,
    val readReport: Boolean = false,
    val validityPeriod: Int? = null,  // Validity period in minutes
    val status: DeliveryStatus = DeliveryStatus.PENDING,
    val parts: Int = 1,                // Number of message parts
    val port: Int? = null,             // Destination port for binary SMS
    val attachments: List<Attachment> = emptyList(),
    val metadata: Map<String, String> = emptyMap()
)

/**
 * MMS/RCS attachment model
 */
data class Attachment(
    val id: String,
    val type: AttachmentType,
    val uri: String,
    val mimeType: String,
    val fileName: String,
    val size: Long,
    val contentId: String? = null
)

enum class AttachmentType {
    IMAGE,
    VIDEO,
    AUDIO,
    VCARD,
    DOCUMENT,
    OTHER
}

/**
 * Test scenario configuration
 */
data class TestScenario(
    val id: String,
    val category: TestCategory,
    val name: String,
    val description: String,
    val rfcReferences: List<String>,
    val messageType: MessageType,
    val defaultConfig: TestConfiguration,
    val testParameters: TestParameters,
    val expectedOutcome: ExpectedOutcome,
    val difficulty: TestDifficulty,
    val requiresRoot: Boolean = false,
    val carrierDependent: Boolean = false,
    val rfcCompliance: List<String> = emptyList(),  // RFC numbers
    val enabled: Boolean = true
)

/**
 * Test Category Enumeration
 */
enum class TestCategory {
    SMS_TEXT,
    SMS_BINARY,
    SMS_FLASH,
    SMS_SILENT,
    MMS_BASIC,
    MMS_MULTIMEDIA,
    RCS_MESSAGING,
    RCS_FILE_TRANSFER,
    CONCATENATION,
    ENCODING,
    DELIVERY_REPORTS,
    STRESS_TESTING,
    AT_COMMANDS,
    NETWORK_TESTING
}

/**
 * Test Configuration
 */
data class TestConfiguration(
    val encoding: SmsEncoding = SmsEncoding.AUTO,
    val messageClass: MessageClass = MessageClass.NONE,
    val priority: Priority = Priority.NORMAL,
    val deliveryReport: Boolean = false,
    val readReport: Boolean = false,
    val validityPeriod: Int = 24, // hours
    val port: Int? = null,
    val repeatCount: Int = 1,
    val delayBetweenMessages: Long = 0, // milliseconds
    val randomizeContent: Boolean = false,
    val maxMessageLength: Int? = null,
    val useAtCommands: Boolean = false,
    val testBody: String = "",
    val attachments: List<String> = emptyList()
)

/**
 * Expected Test Outcome
 */
data class ExpectedOutcome(
    val shouldSendSuccessfully: Boolean = true,
    val shouldBeDelivered: Boolean = true,
    val shouldBeReceived: Boolean = true,
    val shouldBeVisible: Boolean = true,
    val expectedParts: Int = 1,
    val expectedEncoding: SmsEncoding? = null,
    val expectedClass: MessageClass? = null,
    val rfcCompliance: List<String> = emptyList(),
    val notes: String = ""
)

/**
 * Test Difficulty Level
 */
enum class TestDifficulty {
    BASIC,      // Simple test, expected to pass on all devices
    INTERMEDIATE, // May have carrier-specific behavior
    ADVANCED,    // Requires specific configuration
    EXPERT       // Requires root, special permissions, or rare conditions
}

/**
 * Test parameters for various scenarios
 */
data class TestParameters(
    val repeatCount: Int = 1,
    val delayBetweenMessages: Long = 0,  // milliseconds
    val randomizeContent: Boolean = false,
    val testConcatenation: Boolean = false,
    val testUnicode: Boolean = false,
    val testSpecialChars: Boolean = false,
    val maxLength: Int? = null,
    val customHeaders: Map<String, String> = emptyMap()
)

/**
 * Test result model
 */
data class TestResult(
    val scenarioId: String,
    val messageId: String,
    val startTime: Date,
    val endTime: Date? = null,
    val status: TestStatus,
    val deliveryStatus: DeliveryStatus,
    val errors: List<String> = emptyList(),
    val metrics: TestMetrics? = null,
    val rfcViolations: List<String> = emptyList()
)

enum class TestStatus {
    RUNNING,
    PASSED,
    FAILED,
    TIMEOUT,
    CANCELLED
}

/**
 * Performance metrics
 */
data class TestMetrics(
    val sendDuration: Long,        // milliseconds
    val deliveryDuration: Long?,   // milliseconds
    val messageSize: Int,          // bytes
    val partsSent: Int,
    val partsReceived: Int
)

/**
 * Device information
 */
data class DeviceInfo(
    val manufacturer: String,
    val model: String,
    val brand: String,
    val device: String,
    val hardware: String,
    val board: String,
    val androidVersion: String,
    val sdkInt: Int,
    val basebandVersion: String
)

/**
 * Modem information
 */
data class ModemInfo(
    val chipset: ModemChipset,
    val radioType: RadioType,
    val modemDevicePaths: List<String>,
    val atCommandMethod: AtCommandMethod,
    val supportsDirectModemAccess: Boolean
)

/**
 * Supported modem chipsets
 */
enum class ModemChipset(val displayName: String) {
    QUALCOMM_GENERIC("Qualcomm Generic"),
    QUALCOMM_MSM7XXX("Qualcomm MSM7xxx"),
    QUALCOMM_MSM8XXX("Qualcomm MSM8xxx"),
    QUALCOMM_SDM("Qualcomm Snapdragon (SDM)"),
    MEDIATEK_GENERIC("MediaTek Generic"),
    MEDIATEK_HELIO("MediaTek Helio"),
    MEDIATEK_DIMENSITY("MediaTek Dimensity"),
    SAMSUNG_EXYNOS("Samsung Exynos"),
    HISILICON_KIRIN("HiSilicon Kirin"),
    INTEL_XMM("Intel XMM"),
    SPREADTRUM("Spreadtrum/UNISOC"),
    UNKNOWN("Unknown")
}

/**
 * Radio technology types
 */
enum class RadioType(val displayName: String) {
    GSM("GSM/UMTS/HSPA"),
    CDMA("CDMA/EVDO"),
    LTE("LTE (4G)"),
    NR_5G("5G NR"),
    UNKNOWN("Unknown")
}

/**
 * AT command communication methods
 */
enum class AtCommandMethod {
    QCRIL_SMD,          // Qualcomm SMD (Shared Memory Device)
    MEDIATEK_CCCI,      // MediaTek CCCI (Cross Core Communication Interface)
    SAMSUNG_IPC,        // Samsung IPC (Inter-Processor Communication)
    HUAWEI_APPVCOM,     // Huawei/HiSilicon APPVCOM
    INTEL_TTY,          // Intel modem TTY
    SPREADTRUM_STTY,    // Spreadtrum STTY
    STANDARD_TTY,       // Standard TTY/USB
    UNKNOWN             // Unknown/Generic
}

/**
 * SMS sending strategies
 */
enum class SmsStrategy {
    AT_COMMANDS_PRIMARY,    // Use AT commands as primary method
    AT_WITH_FALLBACK,       // Try AT commands, fallback to standard API
    STANDARD_API_ONLY       // Use only standard Android SMS API
}
