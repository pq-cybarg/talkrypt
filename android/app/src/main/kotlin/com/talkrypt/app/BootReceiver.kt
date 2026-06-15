package com.talkrypt.app

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent

/**
 * After a reboot, hydrates saved chats into [SessionHub] and starts
 * [ChatService] if any are on the [Persistence.ALWAYS_ON] tier — the service
 * then reconnects them. No-op when there are no always-on chats. Registered for
 * `RECEIVE_BOOT_COMPLETED` in the manifest.
 */
class BootReceiver : BroadcastReceiver() {
    override fun onReceive(ctx: Context, intent: Intent) {
        if (intent.action != Intent.ACTION_BOOT_COMPLETED) return
        SessionHub.hydrate(ctx.applicationContext)
        ChatService.startIfNeeded(ctx.applicationContext)
    }
}
