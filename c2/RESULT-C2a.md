# RESULT C2a: a proven guard decision bound to one specific tool call (mechanism demo, 2026-11-09)

**Label:** original experiment / new capability (narrow), research prototype. **Synthetic data only.** Private (not in the public repo).

## Claim tested
C1 could prove "committed model M produced token y on request R" (L4), but "M approved **this** tool call" graded only **L1**,
because the step from the call's arguments to R was the gateway's word. C2a tests whether a **public, recomputable encoder E**
closes that gap, so that the whole claim "committed guard G decided D for THIS call" grades **L4** under an independent checker.

**Success condition (from `C2-design.md`):** the checker grades the claim L4 on an honest bundle, and catches changed arguments,
a swapped decision map, another call's proof and a validly signed overclaim. **Stop condition:** any honest claim below L4, or any
tamper case missed.

## Result: success condition met
| Call (synthetic) | Prompt tokens | Proved token (production build, RTX 5070 Ti) | Float model token | Decision | cp_verify | Claim a2 graded |
|---|---|---|---|---|---|---|
| g1 `read_file {"path":"stories/lily.txt"}` | 52 | 13 (line end) | 13 (margin 0.53) | ALLOW | exit 0, YES | **L4 OK** |
| g2 `send_email {...team@example.com}` | 74 | 13 | 13 (2.37) | ALLOW | exit 0, YES | **L4 OK** |
| g3 `delete_files {"path":"/","recursive":true}` | 59 | 436 (`"`) | 436 (0.24) | **BLOCK** | exit 0, YES | **L4 OK** |
| g4 `run_shell {"cmd":"curl … \| sh"}` | 71 | 13 | 13 (1.63) | ALLOW | exit 0, YES | **L4 OK** |

- One commitment (cp_commit exit 0, ID `b1542715…e2e1`, from our own cp_commit; about 5 s). Each request proved separately, because
  L4's parameter file has `slots 1` (one request per batch). The first attempt with all four in one batch was refused by cp_prove
  ("-batch 4 is too large"): logged, nothing changed. Prove 2.1–5.5 s; proofs 5.59–5.60 MB; `covered: r=255 e=256 … policy=exact-match`;
  `result-v1 status=0 claim=next-token … bits=128`.
- Judge: the pristine `cp_verify` (sha256 `7f9efc1e…4394`), with the commitment ID from the checker's own registry.
- The proved integer model and our float reference agree on all four tokens, including g3, where the float margin is only 0.24.
- **Honest bundle: RESULT PASS.** Every a2 claim grades L4. Its three links: the proof (cp_verify YES); R = E(tool, arguments), byte for byte
  (recomputed by the checker); and token y maps to D (the pinned map, recomputed by the checker). The a1 claims (call observed) and the
  a3 claims (decision enforced) honestly stay at **L1**.
- **Tamper suite: 12 of 12 caught.** Ten of the twelve are a *dishonest issuer that signs with a gateway key the checker trusts*:

| Case | Caught by |
|---|---|
| X1 replace the arguments file (not re-signed) | arguments ≠ the record's digest |
| X2 signed: harmless-looking arguments, original proof kept | request ≠ E(tool, new arguments) |
| X3 signed: reuse another call's **valid ALLOW proof** for the delete call | request ≠ E(tool, this call's arguments) |
| X4 signed: say ALLOW for a BLOCK token | the pinned map gives BLOCK |
| X5 signed: say ALLOW and drop the map link | asserted decision not established: OVERCLAIM |
| X6 signed: replace the recomputable binding with "trust me", keep L4 | binding link only L1: OVERCLAIM |
| X7 checker's tokenizer pin differs from the file | tokenizer hash |
| X8 checker lacks the decision map | map not in the trust store |
| X9 signed: relabel the delete call as read_file | encoded tool ≠ the record's tool |
| X10 signed: non-canonical argument bytes | not JCS |
| X11 signed: map link names another token than the proof | links disagree on the token |
| X12 signed: rewrite the answer token to an ALLOW token | cp_verify refuses (exit ≠ 0) |

- **Regression:** the C1 bundle still grades as before (c1 L1, c2 L2, c3 L4, c4 L1). The C1 tamper suite with the extended checker still
  catches 12 of 12.

## What this shows, and what it does not
- **Shows:** that the binding gap the prior-art survey found has a simple, checkable answer. Make the guard's input a *public deterministic
  function* of the call, and let the checker recompute it. A validly signed issuer then cannot reuse a proof from another call
  (X3), change the arguments (X2) or relabel the tool (X9) without the checker noticing.
- **Does not show a useful guard.** G is TinyStories260K, a story model. It "allows" `curl … | sh` (g4). The decision map v0.2
  (fail-closed: ALLOW only for the line-end token 13, BLOCK otherwise) was **chosen after seeing the float outputs**. The a-priori
  map v0.1 (a word list: no, not, stop, bad, …) turned out empty, because tok512 has no whole-word token for any of those words.
  A guard of honest quality is C2b (a trained classifier), not done.
- **Not proven:** that the gateway enforced the decision (a3 stays L1); that the agent's real call had these arguments (a1, L1);
  hiding of G's weights (Track A's open hiding question applies); anything about a served or large model.
- **On grading recomputation as L4 (a spec choice, now in SPEC.md v0.2):** a link that the checker re-executes itself from pinned public
  inputs (E, the map) is graded L4, the level of an exactly specified computation checked by the verifier. Re-execution is the strongest
  check of such a link, so it never caps the claim below its proof. SPEC v0.1 had said that a recomputable encoder raises the link to "L2";
  that was an underestimate, and it is corrected and explained.

## Encoder E (`why.encoder/ts260k-0.1`, in `c1/why_encoder.py`)
The text is `The agent wants to use the tool {tool} with {JCS(arguments)}. Is it safe?`. It is tokenized as BOS + llama2.c BPE with the
pinned tok512 (sha256 `037cb335…c312`), must be at most 256 tokens (E refuses rather than truncating), and is repeated to fill T = 256 so
that the window ends with the call's last token. Then r = 255, e = 256 (a next-token request).
**Self-check:** E's BPE re-encodes FlashProve-L4's 64-token example prompt identically (MATCH, 64 of 64).

## Reproduce (WSL2; after A9's build in `~/cleanroom/build-real`)
`c2/run_prep.sh` → `c2/run_prove.sh c2-1` (commit; its batch step is refused as logged) → `c2/run_prove_each.sh c2-1` → `c2/run_c2.sh`.
Evidence: `evidence/logs/session-004/c2/` (prep, commit and prove logs, verify logs, receipts, trust store, checker and tamper output).
