package com.talkrypt.app

import android.graphics.Color

/** Talkrypt color tokens — the app's half of the design system's `styles.css`
 *  (dark neon default). One place to retheme; screens reference these, never
 *  hex literals. Non-theme colors (QR modules, scanner overlay) stay local to
 *  their call sites — they're functional contrast, not palette. */
object Tk {
    val bg = Color.parseColor("#060A0F")         // app & system-bar background
    val panel = Color.parseColor("#0E141C")      // rows, headers, bars, popups
    val field = Color.parseColor("#161F2A")      // inputs, spinners
    val fg = Color.parseColor("#E3F1F4")         // primary text
    val muted = Color.parseColor("#6E8090")      // secondary text, labels, offline
    val accent = Color.parseColor("#22E4FF")     // primary actions, own bubbles, online
    val peerBubble = Color.parseColor("#1A2531") // peer bubbles, DM glyphs
    val amber = Color.parseColor("#FFB84D")      // hosting/connecting states, markings
    val danger = Color.parseColor("#FF5C7A")     // destructive actions, failures
    val onAccent = Color.parseColor("#04141B")   // ink on the bright accent (not white)

    /** Hint text on [field] — `muted` only reaches ~4.1:1 there, under the 4.5:1
     *  WCAG AA floor for small text. A11y-driven; candidate to upstream into the
     *  design system's styles.css. */
    val hint = Color.parseColor("#8FA1B0")
}
