package com.smstest.app.core.model

/**
 * In-memory handoff for pre-populating TestScreen from a chosen TestScenario.
 * ScenariosScreen writes here; TestScreen reads and clears on first composition.
 */
object ScenarioPrefill {
    var pendingMessageType: MessageType? = null
    var pendingBody: String? = null

    fun consume(): Pair<MessageType, String>? {
        val type = pendingMessageType ?: return null
        val body = pendingBody ?: ""
        pendingMessageType = null
        pendingBody = null
        return type to body
    }
}
