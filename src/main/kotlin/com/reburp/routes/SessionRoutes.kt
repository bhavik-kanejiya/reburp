package com.reburp.routes

import burp.api.montoya.MontoyaApi
import com.reburp.*
import io.ktor.http.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import kotlinx.serialization.json.*

// [Montoya Config] - session handling rules have no dedicated Montoya API, so they are read
// and written through Burp's config export/import.
//
// Burp keeps them in the project config, nested under "project_options" -> "sessions". Earlier
// code looked for "sessions" at the root of the *user* config, which never matched: reads
// always returned an empty list, and writes created a stray top-level "sessions" key that Burp
// ignored, so adding a rule answered 200 without adding anything.
//
// Rather than swap one hardcoded path for another, the block is located by probing the shapes
// Burp is known to emit, and writes go back to wherever the read found it. Imports carry only
// the sessions subtree because Burp merges on import - no need to round-trip the whole config.

private val WRAPPERS = listOf("project_options", "user_options", null)

/** Where the session block lives: which config scope, under which wrapper key, and its content. */
private class SessionsAt(val project: Boolean, val wrapper: String?, val sessions: JsonObject?)

private fun JsonObject.sessionsIn(wrapper: String?): JsonObject? = runCatching {
    if (wrapper == null) this["sessions"]?.jsonObject
    else this[wrapper]?.jsonObject?.get("sessions")?.jsonObject
}.getOrNull()

private fun locateSessions(api: MontoyaApi): SessionsAt {
    val exports = listOf<Pair<Boolean, () -> String>>(
        true to { api.burpSuite().exportProjectOptionsAsJson() },
        false to { api.burpSuite().exportUserOptionsAsJson() }
    )
    for ((isProject, export) in exports) {
        val root = runCatching { Json.parseToJsonElement(export()).jsonObject }.getOrNull() ?: continue
        for (wrapper in WRAPPERS) {
            val sessions = root.sessionsIn(wrapper)
            if (sessions != null) return SessionsAt(isProject, wrapper, sessions)
        }
    }
    // No block yet (a project that has never held a rule): write to the documented location.
    return SessionsAt(project = true, wrapper = "project_options", sessions = null)
}

private fun rulesOf(sessions: JsonObject?): JsonArray = runCatching {
    sessions?.get("session_handling_rules")?.jsonObject?.get("rules")?.jsonArray
}.getOrNull() ?: JsonArray(emptyList())

/** Rebuild the sessions subtree with a new rules array, preserving cookie jar, macros and friends. */
private fun importDoc(at: SessionsAt, rules: JsonArray): JsonObject {
    val sessions = at.sessions?.toMutableMap() ?: mutableMapOf()
    val handling = runCatching { sessions["session_handling_rules"]?.jsonObject?.toMutableMap() }
        .getOrNull() ?: mutableMapOf()
    handling["rules"] = rules
    sessions["session_handling_rules"] = JsonObject(handling)

    val block = JsonObject(sessions)
    val wrapper = at.wrapper
    return if (wrapper == null) buildJsonObject { put("sessions", block) }
    else buildJsonObject { put(wrapper, buildJsonObject { put("sessions", block) }) }
}

private fun applySessions(api: MontoyaApi, at: SessionsAt, rules: JsonArray) {
    val doc = importDoc(at, rules).toString()
    if (at.project) api.burpSuite().importProjectOptionsFromJson(doc)
    else api.burpSuite().importUserOptionsFromJson(doc)
}

fun Routing.sessionRoutes(api: MontoyaApi) {
    route("/api/sessions") {

        // List session handling rules
        get("/rules") {
            runCatching {
                call.respond(rulesOf(locateSessions(api).sessions))
            }.onFailure { call.respond(HttpStatusCode.InternalServerError, ErrorResponse(it.message ?: "Error")) }
        }

        // Burp has no add-header session handling action, so this can never work. Its actions
        // are use_cookies, set cookie/param, check session, in-browser recovery, run macro and
        // invoke extension; anything else is silently stripped on import. This used to build a
        // rule with an invented "ADD_HEADER" action and answer 200 for a write Burp discarded,
        // which left callers believing a header was being injected when nothing was.
        post("/rules/add-header") {
            call.respond(
                HttpStatusCode.NotImplemented,
                ErrorResponse(
                    "Burp has no add-header session handling action, so this rule cannot be created. " +
                        "To add a header to outgoing requests use POST /api/proxy/match-replace " +
                        "with rule_type 'request_header'."
                )
            )
        }

        // Delete session rule by index
        delete("/rules/{index}") {
            val index = call.parameters["index"]?.toIntOrNull()
                ?: return@delete call.respond(HttpStatusCode.BadRequest, ErrorResponse("'index' must be an integer"))
            runCatching {
                val at = locateSessions(api)
                val rules = rulesOf(at.sessions).toMutableList()
                val before = rules.size
                if (index < 0 || index >= before)
                    return@runCatching call.respond(HttpStatusCode.NotFound, ErrorResponse("Index $index out of range ($before rules)"))

                rules.removeAt(index)
                applySessions(api, at, JsonArray(rules))

                val after = rulesOf(locateSessions(api).sessions).size
                if (after == before) {
                    call.respond(
                        HttpStatusCode.InternalServerError,
                        ErrorResponse("Burp did not persist the deletion (still $before rules).")
                    )
                } else {
                    call.respond(MessageResponse("Deleted rule at index $index ($after remaining)"))
                }
            }.onFailure { if (!call.response.isCommitted) call.respond(HttpStatusCode.InternalServerError, ErrorResponse(it.message ?: "Error")) }
        }
    }
}
