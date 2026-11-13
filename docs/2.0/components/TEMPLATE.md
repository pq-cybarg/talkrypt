<!--
  2.0 COMPONENT ASSESSMENT RECORD — copy this file to
  docs/2.0/components/<component-slug>.md and fill it in as the component matures.
  This record is the SINGLE SOURCE OF TRUTH for the component's gate status
  (CHARTER.md §1). `ci/honest-scope-check.sh` parses the front-matter keys below:
  a component may set `mainline-eligible: true` ONLY when fv/security-eval/pentest
  are all `pass` with a non-empty evidence link. Keep every claim honest-scope:
  properties are GOALS UNDER EVALUATION, never guarantees (CHARTER.md §2).
-->
---
component: <component-slug>
task: "#1NN"
status: design            # design | plan | implementing | evaluating | mainline-eligible
mainline-eligible: false  # true ONLY when all three gate fields below are `pass` + evidenced
gate:
  fv:
    status: todo          # todo | in-progress | pass | fail
    evidence: ""          # link: formal/<Module>.fst + the CI run, or the Kani harness
  security-eval:
    status: todo
    reviewer: ""          # a DIFFERENT author than the implementer; external preferred
    evidence: ""          # link: the review record + resolution of findings
  pentest:
    status: todo
    evidence: ""          # link: methodology + results of the adversarial attempt
---

# <Component name> — assessment record

## 1. Goal (NOT a guarantee)

One sentence, honest-scope. State the *goal under evaluation*, with its un-verified
qualifier. E.g. "**Goal (under evaluation, not a guarantee):** a symmetric,
OOB-keyed channel with no on-wire asymmetric handshake, so that the traffic does not
carry a cryptographic-handshake fingerprint."

## 2. Threat model (component-local)

- **Assets** this component protects / exposes.
- **Adversary** capabilities it is evaluated against (and explicitly NOT against).
- **The property under evaluation**, stated falsifiably (what a pentest will try to
  break, e.g. "an on-path observer cannot distinguish this channel's frames from
  <cover traffic> better than chance").

## 3. Construction (what it actually does)

The concrete design: primitives, key flow, where the side channel attaches, the
feature flag that gates it (never default-on).

## 4. Fragment assessment (per CHARTER.md §3 / vision thread 4)

| Dimension | This component |
| --- | --- |
| Source / SBOM provenance | <crate(s), version, vendoring, provenance> |
| Crypto primitive choice | <cipher / KDF / sharing scheme + why> |
| Entropy source | <source> |
| Entropy assessment | <how the source is health-checked; NIST SP 800-90B posture> |
| Timing-analysis posture | <constant-time claims + how verified> |

## 5. Gate evidence

### 5a. Formal verification
What is machine-checked, with the model↔code fidelity mapping (the `formal/README.md`
style). Link the `.fst`/`.ec`/Kani harness and the CI run.

### 5b. Independent security evaluation
Reviewer (≠ implementer), scope, findings, and their resolution / accepted-risk
justification.

### 5c. Penetration test
The adversarial methodology that tried to break the §2 property, the results, and —
honestly — "not broken by the tests performed", never "cannot be broken".

## 6. Honest-scope attestation

> This component asserts no "undetectable" / "unbreakable" / "certified" property as
> a guarantee — every security property above is a goal under evaluation, not a
> guarantee. Where a pentest has run, results are worded as "not broken by the tests
> performed", never as an absolute. (CHARTER.md §2.)
