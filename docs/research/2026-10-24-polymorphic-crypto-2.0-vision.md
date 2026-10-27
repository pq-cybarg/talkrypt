# talkrypt 2.0 — Polymorphic cryptographic assembly & covert channels (vision)

**Status: VISION / RESEARCH — not a spec, not scheduled, nothing here is built.**
This records a large forward direction so it is not lost. It is explicitly a
**2.0 revision** to be developed on a **separate branch**, each component
brainstormed into its own design + plan, and gated on **formal verification,
independent security evaluation, and penetration testing** before it influences
mainline. It intentionally overreaches today's architecture; most of it is
research. NOT certified / NOT audited (and this document makes no claim that any
of it is sound — it is a problem statement, not a design).

## Core premise (why 2.0 at all)

Asymmetric cryptography is **detectable as cryptographic communication** — the
structure (key exchange, signatures, large ciphertexts, protocol fingerprints)
is itself a signal. For genuinely *undetected* communication you largely need
**symmetric crypto with out-of-band key sharing**: no on-wire key agreement, no
distinctive handshake, ciphertext that need not look like anything. talkrypt
today is PQ-asymmetric-first (ML-KEM / ML-DSA); 2.0 explores a regime where the
*technique itself* is chosen, mixed, and rotated per chat — including
symmetric-only, OOB-keyed, low-observability modes.

## Threads captured (unordered; each is its own future design)

### 1. Symmetric, OOB-keyed covert channels
- Symmetric encryption with keys shared entirely out of band (QR, NFC, courier,
  pre-shared, physical) — no on-wire asymmetric handshake to fingerprint.
- Side-channel-delivered keying as a first-class feature for **split-keying
  chats**: the keying material for a chat arrives over a *different* route than
  the chat traffic, and the split is **chat-specific** (each chat can define its
  own keying side-channel + policy).

### 2. Multiparticipant Shamir secret sharing (and its limits)
- Shamir `k`-of-`n` sharing to gate a conversation's key on a quorum — which
  produces **web-of-trust-like** behavior: enough participants must be able to
  confirm/contribute for communication to continue.
- **Problem noted:** intermittently-connected participants break a naive quorum —
  if the people holding shares are offline, no one can proceed.
- **Possible shape:** an *onion-like* structure of **multiple coexisting
  secret-shared conversations** that **overlap when all relevant users are
  online** but do not require everyone always-on — layered/overlapping quorums so
  a reachable subset can keep a (narrower) conversation alive, with fuller
  conversations unlocking as more participants coincide. (Open research: how
  layers nest, how keys relate across layers, forward/backward secrecy across
  intermittent overlaps.)

### 3. Side-channel routing per feature
- Generalize "a feature's data can ride a *different* route than the main chat":
  keying, confirmation hints, presence, metadata, decoys — each independently
  routable. Connects to the mainline multi-bearer `Transport` leg model (the
  clean plug-in point) but at a *per-feature*, policy-driven level.

### 4. Fragmentable, compartmentalized components
- Build the crypto/transport stack from **fragmentable components** that can be
  **compartmentalized** and independently assessed:
  - **source / SBOM** provenance per component,
  - **crypto** primitive choice per component,
  - **entropy** source + **entropy assessment** per component,
  - **timing-analysis** resistance per component,
  so a chat's stack is an assembly of vetted, swappable, separately-auditable
  fragments with known provenance and side-channel posture.

### 5. Polymorphic cryptographic technique assembly
- The headline: a chat's cryptographic construction is **assembled** from the
  above fragments under **user control**, and ideally **reconfigurable by an
  MCP/AI control surface** — including chats **built to assume rotation/evolution**
  (the technique set rotates or evolves over the chat's life, by schedule, event,
  or policy). "Polymorphic" = the observable technique changes over time and
  differs per chat, raising the cost of fingerprinting/attack.

## Why this is strictly separate from mainline

- It reopens the **threat model, handshake, and key management** at the root —
  the opposite of the current "don't touch the engine" multi-bearer work.
- It is **research-grade and dangerous to get wrong** (covert-channel and
  custom-crypto claims fail silently); it must be FV + security-eval + pentest
  gated on its own branch before any mainline influence.
- It must **never weaken** the honest-scope posture: no certification/compliance
  claims, and any "undetectable"/"covert" property stays a *goal under
  evaluation*, never an asserted guarantee, until independently tested.

## The one seam mainline should preserve for it

The current multi-bearer design keeps 2.0's plug points clean (noted in that
spec): the `Transport` **leg model** (where covert/side-channel bearers attach),
`BearerSet`/**capability selection** (where per-chat compartmentalized bearer +
technique policy would live), and **framed-leg fragmentation** (where
fragmentable/compartmentalized component routing attaches). Mainline should avoid
foreclosing these; it should not try to build on them.

## Immediate next step (when 2.0 is picked up)

Decompose into independent sub-projects and brainstorm each on the 2.0 branch,
likely starting with (a) the symmetric OOB-keyed covert-channel primitive and
(b) the fragment/compartment component model + SBOM/entropy/timing assessment
harness — because everything else composes on top of those two.
