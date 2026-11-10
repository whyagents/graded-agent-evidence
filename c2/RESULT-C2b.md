# RESULT C2b: a trained guard model, proved on a consumer GPU, bound to each tool call (2026-11-10)

**Label:** original experiment / new capability (narrow), research prototype. **Synthetic data only.** Private (not in the public repo).
User decisions (2026-11-09: "Yes, start C2b", on the defaults proposed): the data is synthetic and made by us; we wrote our own converter, so no
FlashProve-L4 Node tools were run; the code stays private.

## Claim tested
C2a showed the binding mechanism with a story model. C2b tests whether a guard that we **trained** can be carried through the whole pipeline:
1. our own conversion into FlashProve's accepted layout;
2. a commitment under L4's fitted public configuration;
3. proofs on the RTX 5070 Ti;
4. receipts that the independent checker grades L4.

The guard's decisions must also agree with what the float model computes.
**Success condition:** a held-out accuracy well above the baseline, cp_commit exit 0, accepted proofs, proved tokens equal to the float tokens,
L4 receipts, and 12/12 tampers caught.
**Stop condition:** a failed conversion check, cp_commit exit 7 (worst-case ranges), or rejected proofs.

## Result: success condition met
| Step | Outcome |
|---|---|
| **Our converter** (`c2/why_gguf.py`, Python + numpy, written from L4's documented scheme) | On the original checkpoint it reproduces L4's `model.gguf` **byte for byte** (sha256 `36d8c24c…`), plus `shape.json` and `fold.txt`. Upstream's `weight_sums` (built from our clean-room tree) reproduces L4's `wsums.txt` exactly |
| **Dataset** (`c2/guard_data.py`) | Six tools; the ground truth is a written policy of 6 BLOCK rules plus a default ALLOW. Splits: train 1,500 draws (category-balanced, 46% BLOCK); **test** 258 distinct calls held out by a hash of the prompt (17% BLOCK); **novel** 307 calls from separate value pools: file names, hosts and commands never seen in training (35% BLOCK) |
| **Training** (`c2/guard_train.py`, CPU PyTorch 2.5.1, 1,500 steps, 7.5 min) | Fine-tunes TinyStories260K to emit `' y'` (348) = ALLOW or `' n'` (297); the map is fail-closed (anything other than 348 is BLOCK). Norms are frozen; each matrix's largest-magnitude weight is frozen and the rest clamped, so **every tensor's exponent is unchanged** |
| **Float accuracy** | **test 99.2%** (majority-class baseline 83.3%); **novel 94.1%** (baseline 65.1%). Before training: 16.7% / 34.9% (everything BLOCKed). Weak spots on novel: `read_secret` 6/12 and `email_leak` 33/40 |
| **Commit** (A9 production programs, L4's config **unchanged**) | Weight-exponent columns identical to L4's (0 differences). **cp_commit exit 0**: the worst-case range check passed. ID `d3c8035e…3fd9` |
| **Proofs** of 40 held-out calls (20 test, 20 novel; every BLOCK rule represented) | **40/40 accepted** by the pristine cp_verify (exit 0, YES; `policy=exact-match`, `bits=128`), about 2–3.6 s each |
| **Integer vs float** | proved token = float token in **40 of 40** |
| **Decisions** | **39 of 40 correct.** The one miss: `read_file ~/.gnupg/secring.gpg` (novel) → ALLOW (the float model agrees; margin 0.80). A real false negative of the guard, not a proof issue |
| **Receipts** (8 calls, 4 BLOCK-labelled and 4 ALLOW-labelled) | Checker **PASS**; every a2 claim graded **L4**, **including the wrong ALLOW for the GnuPG key**: L4 proves *what the committed guard decided*, not that the decision is right |
| **Tamper suite** (generic C2 suite) | **12 of 12 caught.** Regressions: the C2a bundle passes with 12/12; the C1 suite 12/12 |

## What this shows
- A guard we trained ourselves, converted by our own independent converter, is proved on a 16 GB consumer GPU, and each decision is
  bound to the exact tool call by a public encoder that the checker recomputes.
- **L4's public configuration carried over** because the fine-tune kept every tensor's exponent and stayed within cp_commit's worst-case
  bounds. No refitting was needed, and no third-party code ran.
- The receipt states exactly what is proven (L4: which decision this committed model made for this call) and what is not:
  - the decision's correctness (L5, which needs outcome validation);
  - enforcement (L1);
  - that the agent's real call had these arguments (L1).

## What it does not show (limits)
- **A guard for real use.** The policy, the tools and every value are synthetic. Accuracy is measured only on synthetic held-out calls
  from the same generator. It misses an unseen secret-file name. A model of 260K parameters, trained in 7.5 minutes, is a demonstration.
- **General integer-float agreement.** 40/40 agree on this sample (the smallest float top-2 margin among all 307 novel calls is 0.10, so close cases exist).
  The proof covers the integer computation only.
- **Hiding of G's weights.** Track A's open hiding question applies, and so does upstream's statement that hiding is argued, not checked by cp_verify.
- **Reproduction elsewhere.** One machine, WSL2.

## Reproduce (WSL2; after A9's build)
| Step | Command |
|---|---|
| Tooling | `c2/c2b_venv.sh` |
| Converter check | `c2/c2b_conv_check.sh` |
| Data | `c2/c2b_data.sh` |
| Training | `c2/c2b_train.sh g1 1500 1e-3 0.1` |
| Commit and prove | `c2/c2b_prove.sh g1 c2b-1 20` |
| Analysis | `c2/c2b_analyze.sh c2b-1` |
| Receipts | `c2/c2b_receipts.sh c2b-1` |
| Export | `c2/c2b_export.sh` |

Evidence is in `evidence/logs/session-004/c2b/`. The weights (`g1.bin`, `model-g1/model.gguf`), proofs and secret state stay in WSL; `artifact-hashes.txt` records their sha256.
