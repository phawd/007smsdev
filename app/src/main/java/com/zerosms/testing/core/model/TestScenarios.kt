package com.zerosms.testing.core.model

/**
 * Comprehensive Test Scenario Enumeration
 * 
 * All test scenarios are enumerated with unique IDs, configurations,
 * and expected outcomes for systematic testing.
 */

/**
 * Complete Test Scenario Catalog
 */
object TestScenarios {
    
    // ==================== SMS TEXT TESTS (15 scenarios) ====================
    
    val SMS_TEXT_001 = TestScenario(
        id = "SMS-TEXT-001",
        category = TestCategory.SMS_TEXT,
        name = "Basic GSM 7-bit SMS",
        description = "Send standard SMS with GSM 7-bit encoding, 160 characters max",
        rfcReferences = listOf("GSM 03.40", "GSM 03.38"),
        messageType = MessageType.SMS_TEXT,
        defaultConfig = TestConfiguration(
            encoding = SmsEncoding.GSM_7BIT,
            testBody = "Hello World! This is a test message using GSM 7-bit encoding."
        ),
        testParameters = TestParameters(),
        expectedOutcome = ExpectedOutcome(
            expectedEncoding = SmsEncoding.GSM_7BIT,
            expectedParts = 1,
            rfcCompliance = listOf("GSM 03.40 - Single PDU", "GSM 03.38 - 7-bit encoding")
        ),
        difficulty = TestDifficulty.BASIC
    )
    
    val SMS_TEXT_002 = TestScenario(
        id = "SMS-TEXT-002",
        category = TestCategory.SMS_TEXT,
        name = "UCS-2 Unicode SMS",
        description = "Send SMS with Unicode characters requiring UCS-2 encoding",
        rfcReferences = listOf("GSM 03.40", "GSM 03.38"),
        messageType = MessageType.SMS_TEXT,
        defaultConfig = TestConfiguration(
            encoding = SmsEncoding.UCS2,
            testBody = "Hello 世界! Привет мир! 🌍"
        ),
        
        testParameters = TestParameters(),        expectedOutcome = ExpectedOutcome(
            expectedEncoding = SmsEncoding.UCS2,
            expectedParts = 1,
            rfcCompliance = listOf("GSM 03.38 - UCS-2 encoding")
        ),
        difficulty = TestDifficulty.BASIC
    )
    
    val SMS_TEXT_003 = TestScenario(
        id = "SMS-TEXT-003",
        category = TestCategory.SMS_TEXT,
        name = "Extended GSM Characters",
        description = "Test GSM 7-bit extended character set (escape sequences)",
        rfcReferences = listOf("GSM 03.38 Table 1"),
        messageType = MessageType.SMS_TEXT,
        defaultConfig = TestConfiguration(
            encoding = SmsEncoding.GSM_7BIT,
            testBody = "Extended chars: []{} ^|~ € \\"
        ),
        
        testParameters = TestParameters(),        expectedOutcome = ExpectedOutcome(
            expectedEncoding = SmsEncoding.GSM_7BIT,
            notes = "Extended characters count as 2 characters each"
        ),
        difficulty = TestDifficulty.INTERMEDIATE
    )
    
    val SMS_TEXT_004 = TestScenario(
        id = "SMS-TEXT-004",
        category = TestCategory.SMS_TEXT,
        name = "Maximum Length GSM SMS",
        description = "Send exactly 160 character GSM 7-bit SMS",
        rfcReferences = listOf("GSM 03.40"),
        messageType = MessageType.SMS_TEXT,
        defaultConfig = TestConfiguration(
            encoding = SmsEncoding.GSM_7BIT,
            testBody = "A".repeat(160)
        ),
        
        testParameters = TestParameters(),        expectedOutcome = ExpectedOutcome(
            expectedEncoding = SmsEncoding.GSM_7BIT,
            expectedParts = 1
        ),
        difficulty = TestDifficulty.BASIC
    )
    
    val SMS_TEXT_005 = TestScenario(
        id = "SMS-TEXT-005",
        category = TestCategory.SMS_TEXT,
        name = "Maximum Length UCS-2 SMS",
        description = "Send exactly 70 character UCS-2 SMS",
        rfcReferences = listOf("GSM 03.40", "GSM 03.38"),
        messageType = MessageType.SMS_TEXT,
        defaultConfig = TestConfiguration(
            encoding = SmsEncoding.UCS2,
            testBody = "A".repeat(70)
        ),
        
        testParameters = TestParameters(),        expectedOutcome = ExpectedOutcome(
            expectedEncoding = SmsEncoding.UCS2,
            expectedParts = 1
        ),
        difficulty = TestDifficulty.BASIC
    )
    
    val SMS_TEXT_006 = TestScenario(
        id = "SMS-TEXT-006",
        category = TestCategory.SMS_TEXT,
        name = "Auto Encoding Detection",
        description = "Test automatic encoding selection based on content",
        rfcReferences = listOf("GSM 03.38"),
        messageType = MessageType.SMS_TEXT,
        defaultConfig = TestConfiguration(
            encoding = SmsEncoding.AUTO,
            testBody = "Auto-detect encoding for this message."
        ),
        
        testParameters = TestParameters(),        expectedOutcome = ExpectedOutcome(
            notes = "Should select GSM 7-bit automatically"
        ),
        difficulty = TestDifficulty.BASIC
    )
    
    val SMS_TEXT_007 = TestScenario(
        id = "SMS-TEXT-007",
        category = TestCategory.SMS_TEXT,
        name = "SMS with Delivery Report",
        description = "Request delivery report for sent SMS",
        rfcReferences = listOf("GSM 03.40 Section 9.2.2.1"),
        messageType = MessageType.SMS_TEXT,
        defaultConfig = TestConfiguration(
            deliveryReport = true,
            testBody = "Test message with delivery report"
        ),
        
        testParameters = TestParameters(),        expectedOutcome = ExpectedOutcome(
            shouldBeDelivered = true,
            rfcCompliance = listOf("GSM 03.40 - SMS-STATUS-REPORT")
        ),
        difficulty = TestDifficulty.INTERMEDIATE,
        carrierDependent = true
    )
    
    val SMS_TEXT_008 = TestScenario(
        id = "SMS-TEXT-008",
        category = TestCategory.SMS_TEXT,
        name = "SMS Class 1 (Mobile Storage)",
        description = "Send SMS to mobile storage (default inbox)",
        rfcReferences = listOf("GSM 03.40 Section 9.2.3.9"),
        messageType = MessageType.SMS_TEXT,
        defaultConfig = TestConfiguration(
            messageClass = MessageClass.CLASS_1,
            testBody = "Class 1 SMS - mobile storage"
        ),
        
        testParameters = TestParameters(),        expectedOutcome = ExpectedOutcome(
            expectedClass = MessageClass.CLASS_1,
            shouldBeVisible = true
        ),
        difficulty = TestDifficulty.BASIC
    )
    
    val SMS_TEXT_009 = TestScenario(
        id = "SMS-TEXT-009",
        category = TestCategory.SMS_TEXT,
        name = "SMS Class 2 (SIM Storage)",
        description = "Send SMS to SIM card storage",
        rfcReferences = listOf("GSM 03.40 Section 9.2.3.9"),
        messageType = MessageType.SMS_TEXT,
        defaultConfig = TestConfiguration(
            messageClass = MessageClass.CLASS_2,
            testBody = "Class 2 SMS - SIM storage"
        ),
        
        testParameters = TestParameters(),        expectedOutcome = ExpectedOutcome(
            expectedClass = MessageClass.CLASS_2,
            notes = "May not be visible in standard inbox"
        ),
        difficulty = TestDifficulty.INTERMEDIATE
    )
    
    val SMS_TEXT_010 = TestScenario(
        id = "SMS-TEXT-010",
        category = TestCategory.SMS_TEXT,
        name = "High Priority SMS",
        description = "Send SMS with high priority flag",
        rfcReferences = listOf("GSM 03.40"),
        messageType = MessageType.SMS_TEXT,
        defaultConfig = TestConfiguration(
            priority = Priority.HIGH,
            testBody = "High priority message"
        ),
        
        testParameters = TestParameters(),        expectedOutcome = ExpectedOutcome(
            notes = "Priority display is device/carrier dependent"
        ),
        difficulty = TestDifficulty.INTERMEDIATE,
        carrierDependent = true
    )
    
    val SMS_TEXT_011 = TestScenario(
        id = "SMS-TEXT-011",
        category = TestCategory.SMS_TEXT,
        name = "Urgent Priority SMS",
        description = "Send SMS with urgent priority",
        rfcReferences = listOf("GSM 03.40"),
        messageType = MessageType.SMS_TEXT,
        defaultConfig = TestConfiguration(
            priority = Priority.URGENT,
            testBody = "URGENT: Test message"
        ),
        
        testParameters = TestParameters(),        expectedOutcome = ExpectedOutcome(
            notes = "Highest priority level"
        ),
        difficulty = TestDifficulty.INTERMEDIATE,
        carrierDependent = true
    )
    
    val SMS_TEXT_012 = TestScenario(
        id = "SMS-TEXT-012",
        category = TestCategory.SMS_TEXT,
        name = "SMS with Custom Validity Period",
        description = "Set custom validity period (message expiration)",
        rfcReferences = listOf("GSM 03.40 Section 9.2.3.12"),
        messageType = MessageType.SMS_TEXT,
        defaultConfig = TestConfiguration(
            validityPeriod = 1, // 1 hour
            testBody = "Message valid for 1 hour only"
        ),
        
        testParameters = TestParameters(),        expectedOutcome = ExpectedOutcome(
            notes = "Validity period handled by SMSC"
        ),
        difficulty = TestDifficulty.INTERMEDIATE
    )
    
    val SMS_TEXT_013 = TestScenario(
        id = "SMS-TEXT-013",
        category = TestCategory.SMS_TEXT,
        name = "Empty SMS Body",
        description = "Test behavior with empty message body",
        rfcReferences = listOf("GSM 03.40"),
        messageType = MessageType.SMS_TEXT,
        defaultConfig = TestConfiguration(
            testBody = ""
        ),
        
        testParameters = TestParameters(),        expectedOutcome = ExpectedOutcome(
            shouldSendSuccessfully = false,
            notes = "Should fail validation - empty body not allowed"
        ),
        difficulty = TestDifficulty.BASIC
    )
    
    val SMS_TEXT_014 = TestScenario(
        id = "SMS-TEXT-014",
        category = TestCategory.SMS_TEXT,
        name = "Special Characters SMS",
        description = "Test SMS with various special characters",
        rfcReferences = listOf("GSM 03.38"),
        messageType = MessageType.SMS_TEXT,
        defaultConfig = TestConfiguration(
            encoding = SmsEncoding.AUTO,
            testBody = "Test: !@#$%^&*()_+-=[]{}|;':\",./<>?"
        ),
        
        testParameters = TestParameters(),        expectedOutcome = ExpectedOutcome(
            notes = "Should handle all ASCII special characters"
        ),
        difficulty = TestDifficulty.INTERMEDIATE
    )
    
    val SMS_TEXT_015 = TestScenario(
        id = "SMS-TEXT-015",
        category = TestCategory.SMS_TEXT,
        name = "Emoji SMS",
        description = "Send SMS with emoji characters (requires UCS-2)",
        rfcReferences = listOf("GSM 03.38"),
        messageType = MessageType.SMS_TEXT,
        defaultConfig = TestConfiguration(
            encoding = SmsEncoding.AUTO,
            testBody = "Testing emoji: 😀 😃 😄 😁 🚀 ⭐ ❤️"
        ),
        
        testParameters = TestParameters(),        expectedOutcome = ExpectedOutcome(
            expectedEncoding = SmsEncoding.UCS2,
            notes = "Emoji forces UCS-2 encoding, reduces capacity to 70 chars"
        ),
        difficulty = TestDifficulty.BASIC
    )
    
    // ==================== SMS BINARY TESTS (8 scenarios) ====================
    
    val SMS_BINARY_001 = TestScenario(
        id = "SMS-BINARY-001",
        category = TestCategory.SMS_BINARY,
        name = "Basic Binary SMS",
        description = "Send 8-bit binary data SMS",
        rfcReferences = listOf("GSM 03.40 Section 9.2.3.9"),
        messageType = MessageType.SMS_BINARY,
        defaultConfig = TestConfiguration(
            encoding = SmsEncoding.GSM_8BIT,
            port = 9200,
            testBody = "Binary data payload"
        ),
        
        testParameters = TestParameters(),        expectedOutcome = ExpectedOutcome(
            expectedEncoding = SmsEncoding.GSM_8BIT,
            shouldBeVisible = false,
            notes = "Binary SMS typically not shown in inbox"
        ),
        difficulty = TestDifficulty.INTERMEDIATE
    )
    
    val SMS_BINARY_002 = TestScenario(
        id = "SMS-BINARY-002",
        category = TestCategory.SMS_BINARY,
        name = "Port Addressed Binary SMS",
        description = "Binary SMS with specific destination port",
        rfcReferences = listOf("GSM 03.40"),
        messageType = MessageType.SMS_BINARY,
        defaultConfig = TestConfiguration(
            port = 5000,
            testBody = "Data for port 5000"
        ),
        
        testParameters = TestParameters(),        expectedOutcome = ExpectedOutcome(
            notes = "Application must listen on specified port"
        ),
        difficulty = TestDifficulty.ADVANCED
    )
    
    val SMS_BINARY_003 = TestScenario(
        id = "SMS-BINARY-003",
        category = TestCategory.SMS_BINARY,
        name = "WAP Push SMS",
        description = "Binary SMS simulating WAP Push (port 2948)",
        rfcReferences = listOf("GSM 03.40", "WAP-230-WSP"),
        messageType = MessageType.SMS_BINARY,
        defaultConfig = TestConfiguration(
            port = 2948,
            testBody = "WAP Push data"
        ),
        
        testParameters = TestParameters(),        expectedOutcome = ExpectedOutcome(
            notes = "Mimics MMS notification mechanism"
        ),
        difficulty = TestDifficulty.ADVANCED
    )
    
    val SMS_BINARY_004 = TestScenario(
        id = "SMS-BINARY-004",
        category = TestCategory.SMS_BINARY,
        name = "Maximum Binary Payload",
        description = "Send maximum size binary SMS (140 bytes)",
        rfcReferences = listOf("GSM 03.40"),
        messageType = MessageType.SMS_BINARY,
        defaultConfig = TestConfiguration(
            port = 9200,
            testBody = "X".repeat(140)
        ),
        
        testParameters = TestParameters(),        expectedOutcome = ExpectedOutcome(
            notes = "140 bytes is maximum for single SMS PDU"
        ),
        difficulty = TestDifficulty.INTERMEDIATE
    )
    
    val SMS_BINARY_005 = TestScenario(
        id = "SMS-BINARY-005",
        category = TestCategory.SMS_BINARY,
        name = "Binary SMS with Hex Data",
        description = "Send binary data as hex string",
        rfcReferences = listOf("GSM 03.40"),
        messageType = MessageType.SMS_BINARY,
        defaultConfig = TestConfiguration(
            port = 9200,
            testBody = "48656C6C6F" // "Hello" in hex
        ),
        
        testParameters = TestParameters(),        expectedOutcome = ExpectedOutcome(
            notes = "Test hex encoding conversion"
        ),
        difficulty = TestDifficulty.INTERMEDIATE
    )
    
    val SMS_BINARY_006 = TestScenario(
        id = "SMS-BINARY-006",
        category = TestCategory.SMS_BINARY,
        name = "Binary SMS Port Range Test",
        description = "Test various port numbers",
        rfcReferences = listOf("GSM 03.40"),
        messageType = MessageType.SMS_BINARY,
        defaultConfig = TestConfiguration(
            port = 16000,
            testBody = "High port number test"
        ),
        
        testParameters = TestParameters(),        expectedOutcome = ExpectedOutcome(
            notes = "Valid port range: 0-65535"
        ),
        difficulty = TestDifficulty.INTERMEDIATE
    )
    
    val SMS_BINARY_007 = TestScenario(
        id = "SMS-BINARY-007",
        category = TestCategory.SMS_BINARY,
        name = "OTA Configuration SMS",
        description = "Simulate OTA (Over-The-Air) configuration",
        rfcReferences = listOf("GSM 03.40", "OMA OTA"),
        messageType = MessageType.SMS_BINARY,
        defaultConfig = TestConfiguration(
            port = 49999,
            testBody = "OTA config data"
        ),
        
        testParameters = TestParameters(),        expectedOutcome = ExpectedOutcome(
            notes = "Used for device configuration updates"
        ),
        difficulty = TestDifficulty.ADVANCED
    )
    
    val SMS_BINARY_008 = TestScenario(
        id = "SMS-BINARY-008",
        category = TestCategory.SMS_BINARY,
        name = "SIM Toolkit Binary SMS",
        description = "Binary SMS for SIM Toolkit applications",
        rfcReferences = listOf("GSM 03.40", "GSM 11.14"),
        messageType = MessageType.SMS_BINARY,
        defaultConfig = TestConfiguration(
            port = 27000,
            testBody = "SIM Toolkit command"
        ),
        testParameters = TestParameters(),
        expectedOutcome = ExpectedOutcome(
            notes = "Interacts with SIM card applications"
        ),
        difficulty = TestDifficulty.EXPERT
    )
    
    // ==================== FLASH SMS TESTS (5 scenarios) ====================
    
    val SMS_FLASH_001 = TestScenario(
        id = "SMS-FLASH-001",
        category = TestCategory.SMS_FLASH,
        name = "Basic Flash SMS (Class 0)",
        description = "Send Class 0 Flash SMS with immediate display",
        rfcReferences = listOf("GSM 03.40 Section 9.2.3.9"),
        messageType = MessageType.SMS_FLASH,
        defaultConfig = TestConfiguration(
            messageClass = MessageClass.CLASS_0,
            testBody = "FLASH: Immediate display message"
        ),
        
        testParameters = TestParameters(),        expectedOutcome = ExpectedOutcome(
            expectedClass = MessageClass.CLASS_0,
            shouldBeVisible = true,
            notes = "Should display immediately, not stored by default"
        ),
        difficulty = TestDifficulty.INTERMEDIATE,
        carrierDependent = true
    )
    
    val SMS_FLASH_002 = TestScenario(
        id = "SMS-FLASH-002",
        category = TestCategory.SMS_FLASH,
        name = "Flash SMS via Standard API",
        description = "Send Flash SMS using standard Android API",
        rfcReferences = listOf("GSM 03.40"),
        messageType = MessageType.SMS_FLASH,
        defaultConfig = TestConfiguration(
            messageClass = MessageClass.CLASS_0,
            useAtCommands = false,
            testBody = "Flash SMS via standard API"
        ),
        
        testParameters = TestParameters(),        expectedOutcome = ExpectedOutcome(
            expectedClass = MessageClass.CLASS_0,
            notes = "Standard API method"
        ),
        difficulty = TestDifficulty.INTERMEDIATE
    )
    
    val SMS_FLASH_003 = TestScenario(
        id = "SMS-FLASH-003",
        category = TestCategory.SMS_FLASH,
        name = "Flash SMS via AT Commands",
        description = "Send Flash SMS using AT commands (requires root)",
        rfcReferences = listOf("GSM 03.40", "AT Commands"),
        messageType = MessageType.SMS_FLASH,
        defaultConfig = TestConfiguration(
            messageClass = MessageClass.CLASS_0,
            useAtCommands = true,
            testBody = "Flash SMS via AT commands"
        ),
        testParameters = TestParameters(),
        expectedOutcome = ExpectedOutcome(
            expectedClass = MessageClass.CLASS_0,
            rfcCompliance = listOf("AT+CMGS with Class 0 DCS")
        ),
        difficulty = TestDifficulty.EXPERT,
        requiresRoot = true
    )
    
    val SMS_FLASH_004 = TestScenario(
        id = "SMS-FLASH-004",
        category = TestCategory.SMS_FLASH,
        name = "Long Flash SMS",
        description = "Flash SMS exceeding 160 characters (concatenated)",
        rfcReferences = listOf("GSM 03.40"),
        messageType = MessageType.SMS_FLASH,
        defaultConfig = TestConfiguration(
            messageClass = MessageClass.CLASS_0,
            testBody = "FLASH: " + "This is a very long flash message that exceeds 160 characters. ".repeat(3)
        ),
        
        testParameters = TestParameters(),        expectedOutcome = ExpectedOutcome(
            expectedClass = MessageClass.CLASS_0,
            expectedParts = 2,
            notes = "Multi-part Flash SMS support varies by device"
        ),
        difficulty = TestDifficulty.ADVANCED,
        carrierDependent = true
    )
    
    val SMS_FLASH_005 = TestScenario(
        id = "SMS-FLASH-005",
        category = TestCategory.SMS_FLASH,
        name = "Flash SMS with Unicode",
        description = "Flash SMS with Unicode characters (UCS-2)",
        rfcReferences = listOf("GSM 03.40", "GSM 03.38"),
        messageType = MessageType.SMS_FLASH,
        defaultConfig = TestConfiguration(
            messageClass = MessageClass.CLASS_0,
            encoding = SmsEncoding.UCS2,
            testBody = "⚠️ FLASH: Urgent notification! 🚨"
        ),
        
        testParameters = TestParameters(),        expectedOutcome = ExpectedOutcome(
            expectedClass = MessageClass.CLASS_0,
            expectedEncoding = SmsEncoding.UCS2
        ),
        difficulty = TestDifficulty.INTERMEDIATE
    )
    
    // Continue with remaining test categories...
    
    /**
     * Get all test scenarios as a list
     */
    fun getAllScenarios(): List<TestScenario> {
        return listOf(
            // SMS Text (15)
            SMS_TEXT_001, SMS_TEXT_002, SMS_TEXT_003, SMS_TEXT_004, SMS_TEXT_005,
            SMS_TEXT_006, SMS_TEXT_007, SMS_TEXT_008, SMS_TEXT_009, SMS_TEXT_010,
            SMS_TEXT_011, SMS_TEXT_012, SMS_TEXT_013, SMS_TEXT_014, SMS_TEXT_015,
            
            // SMS Binary (8)
            SMS_BINARY_001, SMS_BINARY_002, SMS_BINARY_003, SMS_BINARY_004,
            SMS_BINARY_005, SMS_BINARY_006, SMS_BINARY_007, SMS_BINARY_008,
            
            // SMS Flash (5)
            SMS_FLASH_001, SMS_FLASH_002, SMS_FLASH_003, SMS_FLASH_004, SMS_FLASH_005
            
            // More scenarios will be added...
        )
    }
    
    /**
     * Get scenarios by category
     */
    fun getScenariosByCategory(category: TestCategory): List<TestScenario> {
        return getAllScenarios().filter { it.category == category }
    }
    
    /**
     * Get scenario by ID
     */
    fun getScenarioById(id: String): TestScenario? {
        return getAllScenarios().firstOrNull { it.id == id }
    }
    
    /**
     * Get scenarios by difficulty
     */
    fun getScenariosByDifficulty(difficulty: TestDifficulty): List<TestScenario> {
        return getAllScenarios().filter { it.difficulty == difficulty }
    }
    
    /**
     * Get scenarios that require root
     */
    fun getRootRequiredScenarios(): List<TestScenario> {
        return getAllScenarios().filter { it.requiresRoot }
    }
    
    /**
     * Get scenarios that are carrier dependent
     */
    fun getCarrierDependentScenarios(): List<TestScenario> {
        return getAllScenarios().filter { it.carrierDependent }
    }
}

