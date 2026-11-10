# Graded agent evidence: a guard's decision on one exact tool call, checked without trusting the issuer

*WHY Research · research prototype · synthetic data only · not independently replicated*

This repository holds the **checker**, the **receipts** and the **logs** of two experiments, C2a and C2b. In them, a small guard model
decides ALLOW or BLOCK for an AI agent's tool call. The decision is proved with Anthropic's open-source research prover
[FlashProve](https://github.com/anthropics/FlashProve), on a consumer RTX 5070 Ti, using our port
[flashprove-consumer-gpu](https://github.com/whyagents/flashprove-consumer-gpu).

Each decision then goes into a signed receipt. The checker grades every claim in the receipt by its weakest link, and recomputes each link
itself instead of trusting whoever signed the receipt.

It is **not** a security product. The guard has 260K parameters, and the policy, the tools and every tool call are synthetic.

## What a receipt claims, and how the checker grades it

Every receipt carries three claims about one tool call:

| Claim | How the checker establishes it | Level |
|---|---|---|
| a1: the gateway observed this call | the gateway's word | L1 observed |
| a2: committed guard G decided D for **this** call | three links, all re-checked by the checker (below) | L4 computation-proven |
| a3: the gateway enforced D | the gateway's word | L1 observed |

The three links of a2, each re-checked by the checker:

1. **The computation:** G computed token y on request R. The checker runs FlashProve's unmodified `cp_verify` against the commitment ID pinned
   in its own trust store.
2. **The binding:** R = E(tool, arguments). E is a public, deterministic encoder (`c1/why_encoder.py`) over the RFC 8785 canonical arguments.
   The checker re-encodes the call and compares the bytes.
3. **The meaning:** token y means D under a pinned, public decision map. In C2b, `' y'` (token 348) means ALLOW and every other token means
   BLOCK (fail-closed).

L4 means *which decision this committed model computed for this exact call*. It does **not** mean the decision is right: that would be
L5, outcome-validated, which needs independent tests. One C2b receipt shows the difference. It records the guard **allowing**
`read_file ~/.gnupg/secring.gpg`, a mistake, and it still grades L4.

The levels: L1 observed, L2 tamper-evident, L3 execution-attested, L4 computation-proven, L5 outcome-validated. The format is in [SPEC.md](c1/SPEC.md).

## Results (one machine: RTX 5070 Ti, Ubuntu 24.04 under WSL2)

| | C2a (mechanism demo) | C2b (trained guard) |
|---|---|---|
| Guard | TinyStories260K, a story model (not a guard) | TinyStories260K fine-tuned on a synthetic policy (6 BLOCK rules) |
| Accuracy (float model, held-out synthetic calls) | — | 99.2% on test (majority baseline 83.3%); 94.1% on novel names (baseline 65.1%) |
| Proofs accepted by unmodified `cp_verify` | 4 / 4 | 40 / 40 (about 2–3.6 s each) |
| Proved token = float token | 4 / 4 | 40 / 40 |
| Receipts, a2 graded | 4, all L4 | 8, all L4 |
| Tamper cases caught (with proofs) | 12 / 12 | 12 / 12 |

The full write-ups are [RESULT-C2a.md](c2/RESULT-C2a.md) and [RESULT-C2b.md](c2/RESULT-C2b.md). The raw logs are in [evidence/](evidence/).
In the logs, personal paths have been replaced by `$HOME` and `${WHY_ROOT}`. `SHA256SUMS` describes the files as published.

## Check the receipts yourself

You need only Python 3 and its standard library. We tested with Python 3.12 on Ubuntu 24.04.

```bash
python3 -I -B c1/why_receipt.py
python3 -I -B c1/c1_check.py bundles/c2b/bundle bundles/c2b/trust.json -
```

The first command self-tests the Ed25519 and JCS code against RFC 8032 test vectors.

The second checks the C2b bundle without a judge (`-`). It verifies every signature and the hash chain, and it recomputes links 2 and 3
(the encoder and the decision map). It reports link 1 as **NOT RE-CHECKED** and ends with `RESULT: INCOMPLETE` (exit code 3), because
re-checking a proof needs the proof file and `cp_verify`. The checker never reports PASS for a link it did not re-check.

To re-check link 1 as well:
1. Build `cp_verify` from FlashProve commit `9e2bdd8f` (upstream's instructions).
2. Download `c2a-proofs.tar.gz` and `c2b-proofs.tar.gz` from the [v0.1 release](https://github.com/whyagents/graded-agent-evidence/releases/tag/v0.1).
   Unpack them in the repository's top folder (`tar -xzf c2b-proofs.tar.gz`), which puts each proof into `bundles/<run>/bundle/artifacts/fp/`.
   `sha256sum -c bundles/PROOFS.sha256` then confirms the files; the checker also compares each proof with the digest in its signed receipt.
3. Run the same command with the path of your `cp_verify` in place of `-`.

`trust.json` pins the sha256 of *our* `cp_verify` build (`7f9efc1e…4394`). If your build hashes differently, the checker stops with a setup
error. Then decide yourself whether to trust your build, and if so put its hash into your own copy of `trust.json`. With the proofs, the
expected output is `evidence/c2b/c2b-1/receipts.txt`, section `=== checker`.

**The trust store is the checker's input, not the issuer's.** In real use an auditor would obtain `trust.json` from a source they trust.
It holds the gateway's public key, the commitment ID, the encoder and tokenizer pins, the decision map and the judge's hash. Here it sits
beside each bundle for convenience. The entry naming what the commitment *is* ("guard G = …") is our own statement.

## The tamper suite

`c2/c2_tamper.py` makes 12 forged copies of a bundle and expects the checker to reject each one for the right reason. Most are forged by a
**dishonest issuer that signs with a key the checker trusts**. Examples:
- reusing another call's valid ALLOW proof;
- swapping in harmless-looking arguments;
- relabelling the tool;
- writing ALLOW over a proved BLOCK.

With the proofs, all 12 are caught (`evidence/c2b/c2b-1/receipts.txt`). On the proof-free bundles in this repository, 9 of the 12 are
caught. The other 3 can be detected only through the proof itself. On a proof-free bundle the checker reports them as INCOMPLETE, never as
PASS (`evidence/checker-v0.2.1-test.txt`).

## What is not here

- **The guard's weights** (checkpoint and GGUF) and **the training and conversion code.** Only sha256 hashes are recorded, in
  `evidence/*/artifact-hashes.txt`. The synthetic dataset *is* included (`evidence/c2b/data/`), because the accuracy figures rest on it.
- **FlashProve's secret commitment state** (`isk/`) and the worst-case tables.
- **The proofs are not in git.** They are a release download (see "Proofs" below).
- **Scripts that ran inside our private workspace.** `RESULT-C2b.md` names some of them, such as `c2b_*.sh`, `guard_*.py` and
  `why_gguf.py`. They are not published.

## Proofs

The 12 proof files behind the receipts are attached to the [v0.1 release](https://github.com/whyagents/graded-agent-evidence/releases/tag/v0.1)
as two archives:
- `c2a-proofs.tar.gz`: 4 proofs;
- `c2b-proofs.tar.gz`: 8 proofs.

Each proof is about 5.6 MB, about 67 MB in all, which is why they are not kept in git history. Their sha256 are in
`bundles/PROOFS.sha256`, and every receipt also carries its proof's sha256 under its signature. The guard model and the data are
synthetic, so the proofs contain nothing confidential. We make no claim that the proofs hide the guard's weights (see Limits).

## Limits

- **Synthetic policy, tools and data; a 260K-parameter guard.** The accuracy figures hold only for calls from the same generator. On
  unseen file names the guard misses a secret-key read.
- **Weight hiding is not shown.** FlashProve's `cp_verify` does not check hiding, and our patched prover has not been compared byte for byte
  with unmodified upstream. See [HIDING.md](https://github.com/whyagents/flashprove-consumer-gpu/blob/main/docs/HIDING.md).
- **Enforcement (a3) and the agent's real call (a1) rest on the gateway's word,** and the receipts say so.
- **The guard sees at most 256 tokens.** E refuses longer calls (so they are BLOCKed) and never truncates them.
- **The prototype's Ed25519 is not constant-time** and must not be used for real keys. The demo signing keys were made fresh for each run
  and never written to disk, so only their public halves exist.
- **The verifier is FlashProve's tested C++ `cp_verify`, not the Lean-proved one,** which does not accept this proof format.
- **One machine, not independently replicated.**

## Licence

Our code and documents: Apache-2.0 (`LICENSE`). Third-party files are listed in `NOTICE`:
- FlashProve-L4's public prover configuration, in `bundles/*/bundle/artifacts/fp/config/` (Apache-2.0);
- `bundles/tok512.bin` from Karpathy's llama2.c / TinyStories (MIT; `licenses/TinyStories-llama2c.LICENSE`).

FlashProve is © Anthropic PBC (Apache-2.0).
