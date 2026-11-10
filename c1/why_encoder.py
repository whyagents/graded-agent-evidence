#!/usr/bin/env python3
"""WHY public request encoder E, for experiment C2a (research prototype). Standard library only.

E maps one tool call (tool name + arguments) to the exact FlashProve request bytes a guard model is proved on.
It is public and deterministic, so a checker recomputes E(tool, arguments) itself and compares it byte for byte with
the proved request. That is what binds an L4 inference proof to THIS call's arguments.

Encoder 'why.encoder/ts260k-0.1':
  1. text = TEMPLATE.format(tool=tool, args=JCS(arguments))   (RFC 8785, via why_receipt.jcs)
  2. ids  = [1 (BOS)] + llama2.c BPE encoding of text with the pinned tok512 tokenizer (dummy-prefix space, UTF-8
            code points, byte fallback <0xXX> = byte + 3, then greedy merges by highest score), as in llama2.c run.c encode()
  3. len(ids) must be <= T = 256, else E refuses (no truncation)
  4. window = the last T tokens of ids repeated (ids * ceil(T/len)), so the window ENDS with the call's last token
     (FlashProve-L4's example request is the same scheme: its 64-token prompt, 4 times)
  5. request = T little-endian uint32 tokens, then r = T-1 and e = T (a next-token request: the proof is about y alone)
"""
import hashlib
import math
import struct

import why_receipt as wr

ENCODER_ID = 'why.encoder/ts260k-0.1'
TEMPLATE = 'The agent wants to use the tool {tool} with {args}. Is it safe?'
T = 256


class Tokenizer:
    def __init__(self, path, vocab_size=512):
        b = open(path, 'rb').read()
        self.sha256 = hashlib.sha256(b).hexdigest()
        (self.maxlen,) = struct.unpack_from('<i', b, 0)
        off, self.vocab, self.scores = 4, [], []
        for _ in range(vocab_size):
            score, n = struct.unpack_from('<fi', b, off); off += 8
            self.vocab.append(b[off:off + n]); self.scores.append(score); off += n
        if off != len(b):
            raise ValueError('tokenizer: %d trailing bytes (wrong vocab size?)' % (len(b) - off))
        self.index = {}
        for i, p in enumerate(self.vocab):
            self.index.setdefault(p, i)   # first id wins, as llama2.c's bsearch over a sorted copy would for unique pieces

    def encode(self, text):
        """llama2.c run.c encode(text, bos=0, eos=0)."""
        data = text.encode('utf-8')
        toks = []
        if data:
            toks.append(self.index[b' '])           # add_dummy_prefix
        i = 0
        while i < len(data):                       # one UTF-8 code point at a time
            j = i + 1
            while j < len(data) and (data[j] & 0xC0) == 0x80 and j - i < 4:
                j += 1
            cp = data[i:j]
            if cp in self.index:
                toks.append(self.index[cp])
            else:
                toks.extend(c + 3 for c in cp)     # byte fallback: <0x00> is id 3
            i = j
        while True:                                 # merge the best-scoring adjacent pair, repeatedly
            best, bi, bid = -1e10, -1, -1
            for k in range(len(toks) - 1):
                m = self.vocab[toks[k]] + self.vocab[toks[k + 1]]
                t = self.index.get(m)
                if t is not None and self.scores[t] > best:
                    best, bi, bid = self.scores[t], k, t
            if bi < 0:
                break
            toks[bi:bi + 2] = [bid]
        return toks

    def piece(self, tok):
        return self.vocab[tok].decode('utf-8', 'replace')


def prompt_text(tool, arguments):
    return TEMPLATE.format(tool=tool, args=wr.jcs(arguments))


def prompt_ids(tok, tool, arguments):
    ids = [1] + tok.encode(prompt_text(tool, arguments))
    if len(ids) > T:
        raise ValueError('E refuses: %d tokens > T = %d' % (len(ids), T))
    return ids


def encode_request(tok, tool, arguments):
    """The request bytes E(tool, arguments)."""
    ids = prompt_ids(tok, tool, arguments)
    window = (ids * math.ceil(T / len(ids)))[-T:]
    return struct.pack('<%dI' % (T + 2), *window, T - 1, T)


def decision(dmap, token):
    """A pinned decision map. Either a block list {'block': [ids], 'default': 'ALLOW'} or a fail-closed allow list
    {'allow': [ids], 'default': 'BLOCK'}. Returns 'ALLOW' or 'BLOCK'."""
    if 'allow' in dmap:
        return 'ALLOW' if token in set(dmap['allow']) else dmap['default']
    return 'BLOCK' if token in set(dmap['block']) else dmap['default']
