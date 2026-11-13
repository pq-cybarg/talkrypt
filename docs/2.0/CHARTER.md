# talkrypt 2.0 — branch charter and gate

**Status: RESEARCH BRANCH. Nothing here is built, scheduled, or independently
verified — not certified, not audited, not proven. Every capability on this branch
is a GOAL UNDER EVALUATION until it has independently passed the gate below. This
branch MUST NOT influence mainline (`main`) until a component passes that gate.**

This charter governs the `2.0` branch and every component developed under it. It
exists because 2.0 reopens the **threat model, handshake, and key management** at
the root (see [`vision.md`](vision.md)) — the opposite of mainline's "don't touch
the engine" posture — and because covert-channel and custom-crypto claims **fail
silently**. The cost of a wrong, confident claim here is a user who believes they
trust a low-observability claim that was never verified. So the bar is: *prove it,
have it evaluated, have it attacked — or it does not ship.*

## 1. The gate (every component must pass all three before mainline influence)

A 2.0 component is **mainline-eligible** only when its assessment record (see
[`components/TEMPLATE.md`](components/TEMPLATE.md)) records **PASS**, with linked
evidence, for all three of:

1. **Formal verification (FV).** The component's security-relevant logic is
   machine-checked (F\* / EasyCrypt / Kani, in the `formal/` tradition) — totality
   of attacker-reachable decoders, and the stated secrecy / authentication /
   authorization properties by reduction to the assumed primitives. CI-gating.
2. **Independent security evaluation.** A review by someone who did **not** write
   the component, against its stated threat model, with findings recorded and
   resolved (or accepted with written justification). An external reviewer is
   preferred; at minimum, a different author than the implementer.
3. **Penetration test.** An adversarial test that actively tries to break the
   component's claimed property (detect the "covert" channel, recover a split key
   without the side channel, reconstruct below the Shamir quorum, fingerprint the
   "polymorphic" assembly). Methodology and results recorded.

FV is automatable and is enforced in CI by [`.github/workflows/2.0-gate.yml`](../../.github/workflows/2.0-gate.yml).
Security-evaluation and pentest are human processes; the gate enforces that a
component's record **cannot be marked `mainline-eligible: true` without all three
PASS fields and their evidence links** (checked by `ci/honest-scope-check.sh`).

## 2. The honest-scope invariant (non-negotiable, CI-enforced)

Inherited and **strengthened** from mainline (`CLAUDE.md`, the README banner):

- **No** certification / compliance / accreditation claim, ever. "CNSA-aligned"
  means algorithm choice only.
- Low-observability properties are **goals under evaluation, never guarantees**: words
  like "undetectable" / "unobservable" / "untraceable" / "unbreakable" may not be
  asserted as achieved, and must be written as a goal with an explicit un-verified /
  under-evaluation qualifier, until an independent pentest has tried and failed to
  break the property; and even then it is worded as "not broken by the tests
  performed", never as an absolute. ("Covert channel" names a feature and is fine; the
  forbidden thing is claiming the property is achieved.)

`ci/honest-scope-check.sh` scans this branch for unhedged guarantee-language and
fails the build on a violation. It is the automated half of the invariant; the
reviewer is the other half.

## 3. Sub-project decomposition (each its own design + plan + record)

Per the vision's "immediate next step", the line decomposes into independent
components, brainstormed and designed one at a time on this branch. The two
foundations (symmetric OOB-keyed channel; fragment/compartment model) come first
because everything composes on them.

| Component | Task | Depends on | One-line goal (NOT a guarantee) |
| --- | --- | --- | --- |
| Symmetric OOB-keyed covert channel | #123 | foundation | symmetric cipher, keys shared entirely out of band; **goal:** no on-wire asymmetric handshake to fingerprint |
| Fragment / compartment component model | #124 | foundation | stack assembled from vetted, swappable fragments with per-fragment SBOM / crypto / entropy / timing assessment |
| Side-channel-delivered keying / split-keying | #125 | #123 | a chat's keying rides a *different* route than its traffic; split is chat-specific |
| Per-feature side-channel routing | #126 | #124 | keying / confirmation / presence / decoys each independently routable per policy |
| Multiparticipant Shamir `k`-of-`n` quorum | #127 | foundation | quorum-gated conversation key (web-of-trust-like) |
| Intermittent-quorum overlapping conversations | #128 | #127 | onion-like overlapping secret-shared layers for intermittently-connected quorums |
| Polymorphic technique assembly | #129 | #123, #124, #126 | per-chat, time-rotating cryptographic construction; **goal:** raise fingerprinting cost |
| MCP / AI-controllable reconfiguration surface | #130 | #129 | the assembly is reconfigurable by a controlled MCP/AI surface |

## 4. How work flows on this branch

1. A component starts as a **design doc** under `docs/2.0/` (brainstormed first),
   then a **numbered TDD implementation plan** (the mainline `docs/plans/` style).
2. Implementation lands on a sub-branch off `2.0`, TDD, behind a feature flag,
   never enabled by default.
3. Its [assessment record](components/TEMPLATE.md) is filled as FV / security-eval
   / pentest complete. The record is the single source of truth for gate status.
4. Only when the record is all-PASS may the component be proposed for mainline —
   and even then as an opt-in, honest-scope-worded feature.

## 5. The one seam mainline preserves for 2.0

Mainline's multi-bearer design keeps 2.0's plug points clean and must not foreclose
them (it must not try to build on them): the `Transport` **leg model** (where
covert / side-channel bearers attach), `BearerSet` / **capability selection**
(where per-chat compartmentalized bearer + technique policy lives), and **framed-leg
fragmentation** (where fragmentable component routing attaches). See the multibearer
spec.

---

**If you are reading this in a component PR:** the component is not real yet. It is
a research artifact under evaluation. Describe it to a user as what it is — an
unverified goal being tested — never as achieving an "undetectable" / "unbreakable"
property (that remains a goal under evaluation, not a guarantee).
