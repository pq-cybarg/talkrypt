# Reliable `Transport` over broadcast LoRa — Design

**Status:** design + build. Deferred mesh feature **2/4** (the keystone: enables
full mesh-native talkrypt — handshake, group commits, messaging — entirely over
LoRa, not just the message overlay of #56). Lossy behaviour validated over a
deterministic drop-mock; RF validated on hardware.

**Goal:** implement `talkrypt_transport::Transport` over a `MeshNode` broadcast
medium, so the *unchanged* talkrypt engine (which dials `Endpoint`s and exchanges
`Stream` frames) can run over LoRa.

## The problem

`Transport` is connection-oriented + reliable (`listen`→`Listener::accept`→`Stream`,
`dial`→`Stream`, ordered `send_frame`/`recv_frame`). LoRa via a `MeshNode` is
**broadcast, connectionless, lossy, ~200-byte MTU, seconds-latency**. So `MeshTransport`
builds a **pseudo-connection + reliability layer** over the broadcast:

- **Addressing:** every node hears every packet. Connections are identified by a
  64-bit `conn_id` (dialer-chosen); connection *setup* additionally carries short
  endpoint labels so a listener knows a `SYN` is for it. Packets whose `conn_id`
  isn't ours are ignored.
- **Coexistence:** transport packets carry a distinct 2-byte magic (`0xA7 0x74`)
  from the fragmentation codec's (`0xA7 0x6D`), so beacon/messaging fragments and
  transport segments share one mesh channel without cross-parsing.
- **Reliability:** **stop-and-wait ARQ per segment** — the pragmatic correct
  choice for LoRa (tiny bandwidth, high latency; a sliding window buys little and
  risks airtime storms). Each `send_frame` fragments the frame into MTU-sized
  segments and sends them one at a time, awaiting a per-segment ACK with
  timeout + bounded retransmit before the next.

## Packet format (flat, bounded, Kani-provable decode)

Fixed 18-byte header, then a payload:

```text
byte 0-1   magic 0xA7 0x74
byte 2     version = 1
byte 3     type: SYN=0 SYN_ACK=1 DATA=2 DATA_ACK=3 FIN=4
byte 4-11  conn_id (u64 BE)
byte 12-13 msg_seq   (u16 BE)   which message (per connection, per direction)
byte 14-15 frag_idx  (u16 BE)   segment within the message
byte 16-17 frag_cnt  (u16 BE)   segments in the message (>=1)
byte 18..  payload:
             SYN:      src_ep (len u8 ‖ bytes) ‖ dst_ep (len u8 ‖ bytes)
             DATA:     segment bytes
             *_ACK/FIN: empty (conn_id/msg_seq/frag_idx identify what's acked)
```

`parse_packet(&[u8]) -> Option<Packet>` is flat/fixed-offset (Kani-proven total,
like `frag::parse_fragment`); the SYN endpoint sub-fields parse with a bounded
length check.

## Components

- **`MeshTransport { node, channel, local_ep }`** — `impl Transport`. On first
  `listen`/`dial` it spawns ONE reader task that subscribes to the `MeshNode` and
  **demultiplexes** inbound packets: by `conn_id` to the owning connection; a `SYN`
  for our `local_ep` creates a connection and is handed to the `Listener`; a
  `SYN` we don't own is dropped.
- **`MeshListener`** — `accept()` yields a `MeshStream` per inbound connection
  (replies `SYN_ACK`).
- **`MeshStream`** — one pseudo-connection. Inbound packets for its `conn_id` are
  split into an **ack channel** (`*_ACK`) and a **data channel** (`DATA`), so
  `send_frame` and `recv_frame` (post-`into_split`) run concurrently:
  - `send_frame(frame)`: fragment → for each segment, send `DATA` and await its
    `DATA_ACK(msg_seq, frag_idx)`; retransmit on timeout (bounded); `Closed` on
    give-up. `msg_seq` increments per sent frame.
  - `recv_frame()`: collect `DATA` segments (ACK each, dedup by `(msg_seq,
    frag_idx)`), reassemble a full message in `frag_idx` order, deliver in
    `msg_seq` order; return the reassembled frame.

## Security

No new trust: `Transport` already carries **opaque end-to-end ciphertext**; the
mesh transport moves only those frames + its own routing/ARQ headers (never keys
or plaintext). A forged/injected transport packet either fails `parse_packet`
(ignored), targets an unknown `conn_id` (ignored), or delivers ciphertext the
engine's crypto rejects. The reliability layer is not a trust boundary.

## Testing (mock, no radio)

- **Packet codec:** encode↔parse round-trips (all types, SYN endpoints); junk /
  truncation tolerance; Kani proof `parse_packet` is total + in-bounds.
- **`DropOnceMeshNode`** (deterministic lossy decorator): drops the *first*
  transmission of each distinct packet and passes retransmissions — forces exactly
  one retransmit per packet and always converges.
- **End-to-end over the lossy mock:** `dial`/`listen` complete the handshake and a
  multi-segment frame (larger than the MTU) is delivered intact **despite loss**;
  bidirectional; ordering preserved; a second frame reuses the connection.
- **Engine integration (mesh-native):** two `Core`s whose *primary* transport is
  `MeshTransport` over one mock fabric host + join a group and exchange a message —
  proving the whole stack (handshake + group + messaging) runs over LoRa.

## Out of scope

- Sliding-window / selective-repeat (stop-and-wait suffices for LoRa).
- Congestion control beyond the #63 duty-cycle pacing (compose `PacedMeshNode`).
- Multi-hop routing (the mesh firmware already floods; this is end-to-end ARQ).
