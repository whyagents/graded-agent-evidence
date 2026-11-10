# WHY graded receipts v0.1: specification (prototype, research only)

**Goal:** every agent action gets a signed record that states, per claim, **how much is proven**, and an *independent checker*
recomputes that level from the evidence. A record never claims more than its evidence supports.

## Levels (from CLAUDE.md, the evidence levels)
| Level | Meaning | Evidence kinds the v0.1 checker can verify for it |
|---|---|---|
| L1 OBSERVED | a trusted gateway saw it | `gateway_observation` (accepted as the gateway's word; nothing to recompute) |
| L2 TAMPER-EVIDENT | hashed, signed or committed | `signed_statement` (a third party's Ed25519 signature over a digest); `artifact_digest` (the checker recomputes the sha256 of supplied bytes) |
| L3 EXECUTION-ATTESTED | validated hardware or provider attestation | `hardware_attestation`: **no verifier in v0.1**, so it is reported UNVERIFIABLE and grants nothing above L1 |
| L4 COMPUTATION-PROVEN | a valid proof of an exactly specified computation | `zk_inference` (FlashProve). The checker re-runs a pinned `cp_verify` (sha256 checked), using the commitment ID from its **own registry**, never the receipt's; it requires exit 0 and last line `YES` |
| L5 OUTCOME-VALIDATED | independent tests against explicit criteria | no verifier in v0.1 |

## Record
A DSSE v1 envelope (payloadType `application/vnd.why.receipt+json;version=0.1`), signed with the gateway's Ed25519 key over
PAE(type, payload). The payload is RFC 8785 canonical JSON (the subset without floats):
- `schema`: `why.receipt/0.1`; `seq` (0, 1, …); `prev` (the digest of the previous envelope, or null at seq 0); `issued_at`;
- `subject`: `agent`, `session`, and `action` = {`tool`, `arguments_digest` (sha256 of the arguments' JCS)};
- `claims`: a list of {`id`, `statement`, `declared_level`, `why_not_higher`, `links`}. Each **link** is {`what`, `evidence`},
  and each evidence item is one of the kinds above, with the fields that kind needs.

## Grading (the checker)
1. **Record:** the signature is valid for a key in the trust store; the payload is canonical; `seq` and `prev` form an unbroken chain;
   the signed checkpoint's count and head digest match the log. This makes the record itself L2. It is a fact about what the
   gateway *said*, not about the world.
2. **Link level:** the highest level that one of its evidence items supports *and that the checker verified*.
   Unverifiable evidence gives L1 at most: "the gateway asserts it".
3. **Claim level = the minimum over its links** (weakest link).
4. **Verdict per claim:** `OK` if declared ≤ verified; `OVERCLAIM` if declared > verified; `INVALID` if a check that must
   pass fails (a proof refused, a digest mismatch). A receipt passes only if every claim is OK.
5. `why_not_higher` is required below L5. The checker reports which link limits the level.

## Binding a proof to an action (the gap found in prior art)
An L4 link proves that "committed model M produced output y on request R". For the claim **"M approved *this* tool call"**, a second link
must show that R was **derived from this call's arguments**. In v0.1 the demo can only *assert* that derivation (L1), so the whole
claim grades **L1**, and the checker says so. Making the derivation recomputable (a public, deterministic encoder from arguments to
request tokens) raises it to L2. A guard model whose input *is* that encoding (experiment C2) carries the claim to L4.

**v0.2 (C2a, 2026-11-09): done for a mechanism demo.** See `../c2/RESULT-C2a.md`. Two new evidence kinds are recomputed by the checker:
- `encoded_request` {`encoder`, `tool`, `arguments` (artifact: the arguments' JCS bytes), `request`, `request_sha256`}. The checker
  requires: canonical JCS bytes; that sha256 equals the record's `arguments_digest`; that `tool` equals the record's tool; and that the
  request equals **its own** E(tool, arguments) byte for byte (E and the tokenizer hash are pinned in the trust store).
- `decision_map` {`map`, `token`, `decision`}. The checker recomputes the decision from the map pinned in its trust store.

**Grading of recomputed links:** L4. The checker itself re-executes an exactly specified public computation, which is the strongest
check of such a link. (v0.1 above said that a recomputable encoder gives "L2"; that undervalued it.)
**Consistency:** each evidence item reports what the checker established (`request_sha256`, `token`, `decision`), and all links of a
claim must agree, otherwise INVALID. **`asserts`:** a claim's structured content (e.g. `{"decision": "BLOCK", "token": 436}`). Each
value must equal one the checker established; a value that no link establishes makes the claim L0 (so an L4 declaration becomes OVERCLAIM).

**v0.2.1 (2026-11-10): absent evidence.** This exists so that bundles can be published without their proof files.
- **A missing evidence file**, or no judge (`-` in place of `cp_verify`), makes that link L0 with a note starting `MISSING`.
- **NOT RE-CHECKED:** the verdict for a claim that would be OK if every MISSING link passed. A claim that would be an OVERCLAIM even
  then stays an OVERCLAIM.
- **INCOMPLETE:** the result when nothing failed but some claims are NOT RE-CHECKED (exit 3). It is never PASS.

On complete bundles the output is unchanged: byte for byte on the C2b bundle, and the C1, C2a and C2b tamper suites still give 12/12.

## Trust store (given to the checker out of band)
Gateway and tool-server public keys; the commitment registry {commitment ID → model description}; the judge's path and sha256;
(v0.2) `encoders` {id → tokenizer path and sha256, template} and `decision_maps` {id → map}. (v0.2.1) A relative tokenizer path is
resolved against the trust store's own folder.
