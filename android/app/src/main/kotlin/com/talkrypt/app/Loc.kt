package com.talkrypt.app

import android.content.Context

/**
 * Process-global localized-string accessor.
 *
 * Android resolves `getString` against the device's current locale, but many of
 * our string sites live in Context-free layers on purpose — [applyEvent] is
 * documented UI-FREE, and helpers like `ChatNet.friendlyError` are pure. Rather
 * than thread a [Context] through all of them, we hold the Application context
 * once (set in [TkApp.onCreate], which runs before any component) and expose it
 * here. This stays UI-free: it reads string resources, never touches a View.
 *
 * Localization note: system/transcript lines are localized at the moment they're
 * created (then persisted as plain text), so a saved log reads in whatever locale
 * was active when each line was written — the expected behavior for a chat log.
 */
object Loc {
    // Set exactly once in TkApp.onCreate. Using the Application context avoids
    // leaking an Activity and is valid for the whole process lifetime.
    lateinit var ctx: Context

    /** A static string resource. */
    fun s(id: Int): String = ctx.getString(id)

    /** A format-string resource with positional args (e.g. "%1$s", "%2$d"). */
    fun s(id: Int, vararg args: Any?): String = ctx.getString(id, *args)

    /** A quantity string (plurals) — e.g. "1 message" vs "N messages". */
    fun q(id: Int, quantity: Int, vararg args: Any?): String =
        ctx.resources.getQuantityString(id, quantity, *args)
}
