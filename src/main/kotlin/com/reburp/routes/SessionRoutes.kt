package com.reburp.routes

import burp.api.montoya.MontoyaApi
import com.reburp.*
import io.ktor.http.*
import io.ktor.server.request.*
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

        // Add an "add header" session rule
        post("/rules/add-header") {
            val req = runCatching { call.receive<AddHeaderRuleRequest>() }.getOrElse {
                return@post call.respond(HttpStatusCode.BadRequest, ErrorResponse(it.message ?: "Bad body"))
            }
            runCatching {
                val at = locateSessions(api)
                val rules = rulesOf(at.sessions).toMutableList()
                val before = rules.size
                val name = req.name ?: "Add ${req.header_name}"

                rules.add(buildJsonObject {
                    put("enabled", true)
                    put("name", name)
                    put("description", "Auto-added by reburp")
                    putJsonArray("actions") {
                        addJsonObject {
                            put("action_type", "ADD_HEADER")
                            put("header_name", req.header_name)
                            put("header_value", req.header_value)
                        }
                    }
                    if (req.scope_url != null) {
                        putJsonArray("scope_urls") { add(req.scope_url) }
                    }
                })
                applySessions(api, at, JsonArray(rules))

                // Read back before reporting success. This endpoint used to answer 200 for a
                // write Burp silently dropped, which is worse than an error for a caller that
                // then assumes the header is being injected.
                val after = rulesOf(locateSessions(api).sessions).size
                if (after == before) {
                    call.respond(
                        HttpStatusCode.InternalServerError,
                        ErrorResponse("Burp did not persist the rule (still $before). Check that the project config accepts session handling rules.")
                    )
                } else {
                    call.respond(MessageResponse("Session rule '$name' added ($after total)"))
                }
            }.onFailure { if (!call.response.isCommitted) call.respond(HttpStatusCode.InternalServerError, ErrorResponse(it.message ?: "Error")) }
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
