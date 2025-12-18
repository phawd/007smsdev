package com.smstest.app.core.model

/**
 * Extended Test Scenarios - Part 2
 * Silent SMS, Concatenation, Encoding, MMS, RCS, Delivery Reports, Stress Testing
 */

// Add to TestScenarios object
object TestScenariosExtended {
    
    // ==================== SILENT SMS TESTS (6 scenarios) ====================
    
    val SMS_SILENT_001 = TestScenario(
        id = "SMS-SILENT-001",
        category = TestCategory.SMS_SILENT,
        name = "Basic Silent SMS (Type 0)",
        description = "Send Type 0 Silent SMS with PID=0x40",
        rfcReferences = listOf("GSM 03.40 Section 9.2.3.9"),
        messageType = MessageType.SMS_SILENT,
        defaultConfig = TestConfiguration(
            testBody = "Silent ping"
        ),
        
        testParameters = TestParameters(),        expectedOutcome = ExpectedOutcome(
            shouldBeVisible = false,
            shouldBeReceived = true,
            notes = "Type 0 SMS - no user notification"
        ),
        difficulty = TestDifficulty.ADVANCED,
        carrierDependent = true
    )
    
    val SMS_SILENT_002 = TestScenario(
        id = "SMS-SILENT-002",
        category = TestCategory.SMS_SILENT,
        name = "Silent SMS via AT Commands",
        description = "Send Silent SMS using AT commands with PID=0x40",
        rfcReferences = listOf("GSM 03.40", "AT Commands"),
        messageType = MessageType.SMS_SILENT,
        defaultConfig = TestConfiguration(
            useAtCommands = true,
            testBody = "Silent AT command test"
        ),
        
        testParameters = TestParameters(),
        expectedOutcome = ExpectedOutcome(
            shouldBeVisible = false,
            rfcCompliance = listOf("AT+CMGS with PID=0x40")
        ),
        difficulty = TestDifficulty.EXPERT,
        requiresRoot = true
    )
    
    val SMS_SILENT_003 = TestScenario(
        id = "SMS-SILENT-003",
        category = TestCategory.SMS_SILENT,
        name = "Silent SMS Network Ping",
        description = "Network presence check using Silent SMS",
        rfcReferences = listOf("GSM 03.40"),
        messageType = MessageType.SMS_SILENT,
        defaultConfig = TestConfiguration(
            deliveryReport = true,
            testBody = "Network ping"
        ),
        
        testParameters = TestParameters(),        expectedOutcome = ExpectedOutcome(
            shouldBeVisible = false,
            shouldBeDelivered = true,
            notes = "Used for device presence detection"
        ),
        difficulty = TestDifficulty.ADVANCED,
        carrierDependent = true
    )
    
    val SMS_SILENT_004 = TestScenario(
        id = "SMS-SILENT-004",
        category = TestCategory.SMS_SILENT,
        name = "Empty Silent SMS",
        description = "Silent SMS with no body (ping only)",
        rfcReferences = listOf("GSM 03.40"),
        messageType = MessageType.SMS_SILENT,
        defaultConfig = TestConfiguration(
            testBody = ""
        ),
        
        testParameters = TestParameters(),        expectedOutcome = ExpectedOutcome(
            shouldBeVisible = false,
            notes = "Pure network ping, no data"
        ),
        difficulty = TestDifficulty.ADVANCED
    )
    
    val SMS_SILENT_005 = TestScenario(
        id = "SMS-SILENT-005",
        category = TestCategory.SMS_SILENT,
        name = "Silent SMS with Delivery Tracking",
        description = "Monitor delivery status of Silent SMS",
        rfcReferences = listOf("GSM 03.40"),
        messageType = MessageType.SMS_SILENT,
        defaultConfig = TestConfiguration(
            deliveryReport = true,
            testBody = "Tracked silent message"
        ),
        
        testParameters = TestParameters(),        expectedOutcome = ExpectedOutcome(
            shouldBeVisible = false,
            shouldBeDelivered = true,
            notes = "Delivery report should arrive even if message is silent"
        ),
        difficulty = TestDifficulty.ADVANCED,
        carrierDependent = true
    )
    
    val SMS_SILENT_006 = TestScenario(
        id = "SMS-SILENT-006",
        category = TestCategory.SMS_SILENT,
        name = "Silent SMS Burst Test",
        description = "Send multiple Silent SMS in rapid succession",
        rfcReferences = listOf("GSM 03.40"),
        messageType = MessageType.SMS_SILENT,
        defaultConfig = TestConfiguration(
            repeatCount = 10,
            delayBetweenMessages = 100,
            testBody = "Silent burst test"
        ),
        
        testParameters = TestParameters(),        expectedOutcome = ExpectedOutcome(
            shouldBeVisible = false,
            notes = "Tests network handling of rapid silent messages"
        ),
        difficulty = TestDifficulty.EXPERT,
        carrierDependent = true
    )
    
    // ==================== CONCATENATION TESTS (7 scenarios) ====================
    
    val SMS_CONCAT_001 = TestScenario(
        id = "SMS-CONCAT-001",
        category = TestCategory.CONCATENATION,
        name = "2-Part GSM Concatenated SMS",
        description = "Send message requiring 2 parts (161-306 chars GSM)",
        rfcReferences = listOf("GSM 03.40 Section 9.2.3.24"),
        messageType = MessageType.SMS_TEXT,
        defaultConfig = TestConfiguration(
            encoding = SmsEncoding.GSM_7BIT,
            testBody = "Part 1: " + "A".repeat(153) + " Part 2: " + "B".repeat(20)
        ),
        
        testParameters = TestParameters(),        expectedOutcome = ExpectedOutcome(
            expectedParts = 2,
            rfcCompliance = listOf("GSM 03.40 - UDH concatenation")
        ),
        difficulty = TestDifficulty.BASIC
    )
    
    val SMS_CONCAT_002 = TestScenario(
        id = "SMS-CONCAT-002",
        category = TestCategory.CONCATENATION,
        name = "3-Part GSM Concatenated SMS",
        description = "Send message requiring 3 parts",
        rfcReferences = listOf("GSM 03.40"),
        messageType = MessageType.SMS_TEXT,
        defaultConfig = TestConfiguration(
            encoding = SmsEncoding.GSM_7BIT,
            testBody = "Three parts: " + "X".repeat(450)
        ),
        
        testParameters = TestParameters(),        expectedOutcome = ExpectedOutcome(
            expectedParts = 3,
            notes = "Each part: 153 chars (160 - 7 bytes UDH)"
        ),
        difficulty = TestDifficulty.INTERMEDIATE
    )
    
    val SMS_CONCAT_003 = TestScenario(
        id = "SMS-CONCAT-003",
        category = TestCategory.CONCATENATION,
        name = "2-Part UCS-2 Concatenated SMS",
        description = "Unicode message requiring 2 parts (71-134 chars)",
        rfcReferences = listOf("GSM 03.40", "GSM 03.38"),
        messageType = MessageType.SMS_TEXT,
        defaultConfig = TestConfiguration(
            encoding = SmsEncoding.UCS2,
            testBody = "Unicode: " + "世".repeat(70)
        ),
        
        testParameters = TestParameters(),        expectedOutcome = ExpectedOutcome(
            expectedParts = 2,
            expectedEncoding = SmsEncoding.UCS2,
            notes = "Each part: 67 chars (70 - 3 bytes UDH)"
        ),
        difficulty = TestDifficulty.INTERMEDIATE
    )
    
    val SMS_CONCAT_004 = TestScenario(
        id = "SMS-CONCAT-004",
        category = TestCategory.CONCATENATION,
        name = "Maximum Parts Concatenation",
        description = "Send very long message (10+ parts)",
        rfcReferences = listOf("GSM 03.40"),
        messageType = MessageType.SMS_TEXT,
        defaultConfig = TestConfiguration(
            encoding = SmsEncoding.GSM_7BIT,
            testBody = "Long message: " + "Z".repeat(1500)
        ),
        
        testParameters = TestParameters(),        expectedOutcome = ExpectedOutcome(
            expectedParts = 10,
            notes = "Tests maximum concatenation support"
        ),
        difficulty = TestDifficulty.ADVANCED,
        carrierDependent = true
    )
    
    val SMS_CONCAT_005 = TestScenario(
        id = "SMS-CONCAT-005",
        category = TestCategory.CONCATENATION,
        name = "Concatenation with Delivery Reports",
        description = "Multi-part SMS with delivery tracking",
        rfcReferences = listOf("GSM 03.40"),
        messageType = MessageType.SMS_TEXT,
        defaultConfig = TestConfiguration(
            encoding = SmsEncoding.GSM_7BIT,
            deliveryReport = true,
            testBody = "Tracked concat: " + "M".repeat(300)
        ),
        
        testParameters = TestParameters(),        expectedOutcome = ExpectedOutcome(
            expectedParts = 2,
            shouldBeDelivered = true,
            notes = "Each part should have delivery report"
        ),
        difficulty = TestDifficulty.INTERMEDIATE
    )
    
    val SMS_CONCAT_006 = TestScenario(
        id = "SMS-CONCAT-006",
        category = TestCategory.CONCATENATION,
        name = "Mixed Encoding Concatenation Test",
        description = "Test auto-encoding with concatenation",
        rfcReferences = listOf("GSM 03.40", "GSM 03.38"),
        messageType = MessageType.SMS_TEXT,
        defaultConfig = TestConfiguration(
            encoding = SmsEncoding.AUTO,
            testBody = "Auto concat: " + "Mixed content test. ".repeat(15)
        ),
        
        testParameters = TestParameters(),        expectedOutcome = ExpectedOutcome(
            notes = "Should auto-select encoding and concatenate"
        ),
        difficulty = TestDifficulty.INTERMEDIATE
    )
    
    val SMS_CONCAT_007 = TestScenario(
        id = "SMS-CONCAT-007",
        category = TestCategory.CONCATENATION,
        name = "Rapid Concatenated Messages",
        description = "Send multiple concatenated messages quickly",
        rfcReferences = listOf("GSM 03.40"),
        messageType = MessageType.SMS_TEXT,
        defaultConfig = TestConfiguration(
            encoding = SmsEncoding.GSM_7BIT,
            repeatCount = 5,
            delayBetweenMessages = 500,
            testBody = "Rapid concat test: " + "R".repeat(300)
        ),
        
        testParameters = TestParameters(),        expectedOutcome = ExpectedOutcome(
            expectedParts = 2,
            notes = "Stress test for concatenation handling"
        ),
        difficulty = TestDifficulty.ADVANCED
    )
    
    // ==================== ENCODING TESTS (9 scenarios) ====================
    
    val SMS_ENCODING_001 = TestScenario(
        id = "SMS-ENCODING-001",
        category = TestCategory.ENCODING,
        name = "Pure GSM 7-bit Alphabet",
        description = "Test all GSM 7-bit basic characters",
        rfcReferences = listOf("GSM 03.38 Table 0"),
        messageType = MessageType.SMS_TEXT,
        defaultConfig = TestConfiguration(
            encoding = SmsEncoding.GSM_7BIT,
            testBody = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
        ),
        
        testParameters = TestParameters(),        expectedOutcome = ExpectedOutcome(
            expectedEncoding = SmsEncoding.GSM_7BIT,
            rfcCompliance = listOf("GSM 03.38 - Basic character set")
        ),
        difficulty = TestDifficulty.BASIC
    )
    
    val SMS_ENCODING_002 = TestScenario(
        id = "SMS-ENCODING-002",
        category = TestCategory.ENCODING,
        name = "GSM 7-bit Extended Characters",
        description = "Test GSM 7-bit extension table characters",
        rfcReferences = listOf("GSM 03.38 Table 1"),
        messageType = MessageType.SMS_TEXT,
        defaultConfig = TestConfiguration(
            encoding = SmsEncoding.GSM_7BIT,
            testBody = "Extended: |^€{}[~]\\€"
        ),
        
        testParameters = TestParameters(),        expectedOutcome = ExpectedOutcome(
            expectedEncoding = SmsEncoding.GSM_7BIT,
            notes = "Extended chars use escape sequence (2 septets each)"
        ),
        difficulty = TestDifficulty.INTERMEDIATE
    )
    
    val SMS_ENCODING_003 = TestScenario(
        id = "SMS-ENCODING-003",
        category = TestCategory.ENCODING,
        name = "Euro Symbol Encoding",
        description = "Test Euro symbol (€) encoding in GSM",
        rfcReferences = listOf("GSM 03.38"),
        messageType = MessageType.SMS_TEXT,
        defaultConfig = TestConfiguration(
            encoding = SmsEncoding.GSM_7BIT,
            testBody = "Price: €100"
        ),
        
        testParameters = TestParameters(),        expectedOutcome = ExpectedOutcome(
            expectedEncoding = SmsEncoding.GSM_7BIT,
            notes = "Euro is in GSM extended set"
        ),
        difficulty = TestDifficulty.INTERMEDIATE
    )
    
    val SMS_ENCODING_004 = TestScenario(
        id = "SMS-ENCODING-004",
        category = TestCategory.ENCODING,
        name = "Cyrillic Encoding (UCS-2)",
        description = "Test Cyrillic characters requiring UCS-2",
        rfcReferences = listOf("GSM 03.38"),
        messageType = MessageType.SMS_TEXT,
        defaultConfig = TestConfiguration(
            encoding = SmsEncoding.AUTO,
            testBody = "Привет мир! Тест Кириллицы."
        ),
        
        testParameters = TestParameters(),        expectedOutcome = ExpectedOutcome(
            expectedEncoding = SmsEncoding.UCS2,
            notes = "Cyrillic forces UCS-2 encoding"
        ),
        difficulty = TestDifficulty.BASIC
    )
    
    val SMS_ENCODING_005 = TestScenario(
        id = "SMS-ENCODING-005",
        category = TestCategory.ENCODING,
        name = "Chinese Characters (UCS-2)",
        description = "Test Chinese/Japanese/Korean characters",
        rfcReferences = listOf("GSM 03.38"),
        messageType = MessageType.SMS_TEXT,
        defaultConfig = TestConfiguration(
            encoding = SmsEncoding.AUTO,
            testBody = "你好世界！こんにちは 안녕하세요"
        ),
        
        testParameters = TestParameters(),        expectedOutcome = ExpectedOutcome(
            expectedEncoding = SmsEncoding.UCS2,
            notes = "CJK characters require UCS-2"
        ),
        difficulty = TestDifficulty.BASIC
    )
    
    val SMS_ENCODING_006 = TestScenario(
        id = "SMS-ENCODING-006",
        category = TestCategory.ENCODING,
        name = "Arabic Encoding (UCS-2)",
        description = "Test Arabic script encoding",
        rfcReferences = listOf("GSM 03.38"),
        messageType = MessageType.SMS_TEXT,
        defaultConfig = TestConfiguration(
            encoding = SmsEncoding.AUTO,
            testBody = "مرحبا بالعالم اختبار اللغة العربية"
        ),
        
        testParameters = TestParameters(),        expectedOutcome = ExpectedOutcome(
            expectedEncoding = SmsEncoding.UCS2,
            notes = "Arabic requires UCS-2, right-to-left text"
        ),
        difficulty = TestDifficulty.INTERMEDIATE
    )
    
    val SMS_ENCODING_007 = TestScenario(
        id = "SMS-ENCODING-007",
        category = TestCategory.ENCODING,
        name = "Mixed Emoji and Text",
        description = "Test emoji with regular text",
        rfcReferences = listOf("GSM 03.38"),
        messageType = MessageType.SMS_TEXT,
        defaultConfig = TestConfiguration(
            encoding = SmsEncoding.AUTO,
            testBody = "Test 🚀 with emoji 😀 and text"
        ),
        
        testParameters = TestParameters(),        expectedOutcome = ExpectedOutcome(
            expectedEncoding = SmsEncoding.UCS2,
            notes = "Emoji forces UCS-2, reduces capacity"
        ),
        difficulty = TestDifficulty.BASIC
    )
    
    val SMS_ENCODING_008 = TestScenario(
        id = "SMS-ENCODING-008",
        category = TestCategory.ENCODING,
        name = "Accented Characters",
        description = "Test accented Latin characters",
        rfcReferences = listOf("GSM 03.38"),
        messageType = MessageType.SMS_TEXT,
        defaultConfig = TestConfiguration(
            encoding = SmsEncoding.AUTO,
            testBody = "Tëst ÄÖÜ àéèù"
        ),
        
        testParameters = TestParameters(),        expectedOutcome = ExpectedOutcome(
            notes = "Some accents in GSM 7-bit, others force UCS-2"
        ),
        difficulty = TestDifficulty.INTERMEDIATE
    )
    
    val SMS_ENCODING_009 = TestScenario(
        id = "SMS-ENCODING-009",
        category = TestCategory.ENCODING,
        name = "Encoding Boundary Test",
        description = "Test message at exact encoding boundary",
        rfcReferences = listOf("GSM 03.38"),
        messageType = MessageType.SMS_TEXT,
        defaultConfig = TestConfiguration(
            encoding = SmsEncoding.AUTO,
            testBody = "A".repeat(160)
        ),
        
        testParameters = TestParameters(),        expectedOutcome = ExpectedOutcome(
            expectedEncoding = SmsEncoding.GSM_7BIT,
            expectedParts = 1,
            notes = "Exactly 160 GSM chars - single SMS"
        ),
        difficulty = TestDifficulty.BASIC
    )
    
    // Add helper to get all extended scenarios
    fun getAllExtendedScenarios(): List<TestScenario> {
        return listOf(
            // Silent SMS (6)
            SMS_SILENT_001, SMS_SILENT_002, SMS_SILENT_003,
            SMS_SILENT_004, SMS_SILENT_005, SMS_SILENT_006,
            
            // Concatenation (7)
            SMS_CONCAT_001, SMS_CONCAT_002, SMS_CONCAT_003,
            SMS_CONCAT_004, SMS_CONCAT_005, SMS_CONCAT_006, SMS_CONCAT_007,
            
            // Encoding (9)
            SMS_ENCODING_001, SMS_ENCODING_002, SMS_ENCODING_003,
            SMS_ENCODING_004, SMS_ENCODING_005, SMS_ENCODING_006,
            SMS_ENCODING_007, SMS_ENCODING_008, SMS_ENCODING_009
        )
    }
}

