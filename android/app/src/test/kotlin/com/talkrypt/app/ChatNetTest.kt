package com.talkrypt.app

import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.net.InetSocketAddress
import java.net.ServerSocket

/** Each hosted chat needs its own TCP listener, so [ChatNet.allocLanPort] must
 *  hand out a port that isn't already bound — otherwise a second concurrent host
 *  fails to bind ("transport error"). */
class ChatNetTest {
    @Test fun alloc_skips_a_held_port() {
        ServerSocket().use { held ->
            held.bind(InetSocketAddress("0.0.0.0", ChatNet.LAN_PORT))
            val p = ChatNet.allocLanPort()
            assertNotEquals("must not hand out the held base port", ChatNet.LAN_PORT, p)
            assertTrue("steps upward from the base", p > ChatNet.LAN_PORT)
            // The returned port is actually bindable right now.
            ServerSocket().use { it.bind(InetSocketAddress("0.0.0.0", p)) }
        }
    }

    @Test fun alloc_returns_a_bindable_port() {
        val p = ChatNet.allocLanPort()
        assertTrue(p >= ChatNet.LAN_PORT)
        ServerSocket().use { it.bind(InetSocketAddress("0.0.0.0", p)) } // no exception = bindable
    }
}
