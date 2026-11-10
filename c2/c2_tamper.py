#!/usr/bin/env python3
"""C2a tamper suite: each case alters a copy of the good guard bundle; c1_check.py must FAIL with the expected reason.
Most cases are a DISHONEST BUT VALIDLY SIGNING issuer (a gateway key the checker trusts), the hard case for receipts.
usage: python3 -I -B c2_tamper.py GOOD_BUNDLE TRUST_JSON JUDGE
Exit 0 if every case was caught as expected."""
import base64, json, os, shutil, subprocess, sys, tempfile
HERE = os.path.dirname(os.path.abspath(__file__))
C1 = os.path.join(HERE, '..', 'c1')
sys.path.insert(0, C1)
import why_receipt as wr

G3 = 2   # record index of g3 (delete_files "/", proved token 436 -> BLOCK)
G1 = 0   # record index of g1 (read_file, token 13 -> ALLOW)


def load(b):
    return [json.loads(l) for l in open(os.path.join(b, 'receipts.jsonl')) if l.strip()]


def payload(env):
    return json.loads(base64.b64decode(env['payload']))


def claim(p, cid):
    return [c for c in p['claims'] if c['id'] == cid][0]


def link(c, what_prefix):
    return [l for l in c['links'] if l['what'].startswith(what_prefix)][0]


def load_trust(trust):
    """The trust store, with relative tokenizer paths made absolute (the altered copy is written elsewhere)."""
    t = json.load(open(trust))
    for e in t.get('encoders', {}).values():
        if not os.path.isabs(e['tokenizer_path']):
            e['tokenizer_path'] = os.path.join(os.path.dirname(os.path.abspath(trust)), e['tokenizer_path'])
    return t


def resign(b, trust, edit):
    """A dishonest issuer with a trusted gateway key: applies edit(payloads, artifacts_dir), then re-signs and re-chains everything."""
    sk = wr.new_secret(); pub = wr.ed25519_public(sk)
    t = load_trust(trust); t['keys'] = {wr.key_id(pub): {'role': 'gateway', 'public_hex': pub.hex()}}
    json.dump(t, open(os.path.join(b, 'trust.alt.json'), 'w'))
    ps = [payload(e) for e in load(b)]
    edit(ps, os.path.join(b, 'artifacts'))
    prev, out = None, []
    for p in ps:
        p['prev'] = prev; ne = wr.envelope(p, sk); out.append(ne); prev = wr.envelope_digest(ne)
    with open(os.path.join(b, 'receipts.jsonl'), 'w') as f:
        for e in out:
            f.write(wr.jcs(e) + '\n')
    cp = {'schema': 'why.checkpoint/0.1', 'session': ps[0]['subject']['session'], 'count': len(out), 'head': prev}
    json.dump(wr.envelope(cp, sk, 'application/vnd.why.checkpoint+json;version=0.1'), open(os.path.join(b, 'checkpoint.json'), 'w'))


def main():
    global G1, G3
    good, trust, judge = sys.argv[1:4]
    # the first BLOCK record plays "g3", the first ALLOW record "g1" (C2a: records 2 and 0)
    ps0 = [payload(e) for e in load(good)]
    dec = [claim(p, 'a2')['asserts']['decision'] for p in ps0]
    G3, G1 = dec.index('BLOCK'), dec.index('ALLOW')
    z1 = link(claim(ps0[G1], 'a2'), 'G computed')['evidence'][0]
    A_REQ, A_Y, A_PROOF, A_TOK = z1['request'], z1['token_file'], z1['proof'], z1['token']
    z3 = link(claim(ps0[G3], 'a2'), 'G computed')['evidence'][0]
    B_Y = z3['token_file']
    B_ARGS = link(claim(ps0[G3], 'a2'), 'R = E')['evidence'][0]['arguments']
    print('BLOCK record %d (%s), ALLOW record %d (%s, token %d)' % (G3, ps0[G3]['subject']['action']['tool'], G1, ps0[G1]['subject']['action']['tool'], A_TOK))
    cases = []
    case = lambda name, expect, fn: cases.append((name, expect, fn))
    sha = lambda path: wr.sha256_hex(open(path, 'rb').read())

    def x1(b):  # bytes only, no re-signing
        open(os.path.join(b, 'artifacts', B_ARGS), 'wb').write(wr.jcs_bytes({'path': '/tmp/scratch', 'recursive': True}))
    case('X1 replace g3\'s arguments file (no re-signing)', 'INVALID: arguments file differs', x1)

    def x2(b):
        def e(ps, art):
            new = {'path': '/tmp/scratch', 'recursive': True}
            open(os.path.join(art, B_ARGS), 'wb').write(wr.jcs_bytes(new))
            ps[G3]['subject']['action']['arguments_digest'] = 'sha256:' + wr.sha256_hex(wr.jcs_bytes(new))
        resign(b, trust, e)
    case('X2 signed issuer: harmless-looking arguments, original proof kept', 'INVALID: the request is not E(', x2)

    def x3(b):
        def e(ps, art):  # g3 keeps its own arguments but points at g1's (valid, ALLOW) request, token and proof
            c = claim(ps[G3], 'a2'); z = link(c, 'G computed')['evidence'][0]; enc = link(c, 'R = E')['evidence'][0]
            for k, f in (('request', A_REQ), ('token_file', A_Y), ('proof', A_PROOF)):
                z[k] = f
            z['request_sha256'] = sha(os.path.join(art, A_REQ)); z['proof_sha256'] = sha(os.path.join(art, A_PROOF)); z['token'] = A_TOK
            enc['request'] = A_REQ; enc['request_sha256'] = z['request_sha256']
            link(c, 'token y')['evidence'][0].update({'token': A_TOK, 'decision': 'ALLOW'}); c['asserts'] = {'decision': 'ALLOW', 'token': A_TOK}
        resign(b, trust, e)
    case('X3 signed issuer: reuses another call\'s valid ALLOW proof for g3', 'INVALID: the request is not E(', x3)

    def x4(b):
        def e(ps, art):
            c = claim(ps[G3], 'a2'); c['asserts']['decision'] = 'ALLOW'; link(c, 'token y')['evidence'][0]['decision'] = 'ALLOW'
        resign(b, trust, e)
    case('X4 signed issuer: says ALLOW for g3\'s BLOCK token', 'INVALID: the pinned map gives BLOCK', x4)

    def x5(b):
        def e(ps, art):
            c = claim(ps[G3], 'a2'); c['asserts']['decision'] = 'ALLOW'; c['links'] = [l for l in c['links'] if not l['what'].startswith('token y')]
        resign(b, trust, e)
    case('X5 signed issuer: says ALLOW and drops the decision-map link', 'OVERCLAIM', x5)

    def x6(b):
        def e(ps, art):
            c = claim(ps[G3], 'a2'); link(c, 'R = E')['evidence'] = [{'kind': 'gateway_observation', 'note': 'trust me'}]
        resign(b, trust, e)
    case('X6 signed issuer: replaces the recomputable binding with its own word, keeps L4', 'OVERCLAIM', x6)

    def x7(b):
        t = load_trust(trust); [v.update({'tokenizer_sha256': '00' * 32}) for v in t['encoders'].values()]
        json.dump(t, open(os.path.join(b, 'trust.alt.json'), 'w'))
    case('X7 checker\'s pinned tokenizer hash differs from the file', 'INVALID: tokenizer file differs', x7)

    def x8(b):
        t = load_trust(trust); t['decision_maps'] = {}; json.dump(t, open(os.path.join(b, 'trust.alt.json'), 'w'))
    case('X8 checker\'s trust store lacks the decision map', 'INVALID: decision map not in', x8)

    def x9(b):
        def e(ps, art):
            t = ps[G3]['subject']['action']['tool']
            ps[G3]['subject']['action']['tool'] = 'read_file' if t != 'read_file' else 'write_file'
        resign(b, trust, e)
    case('X9 signed issuer: relabels g3 as read_file', 'INVALID: encoded tool', x9)

    def x10(b):
        def e(ps, art):
            raw = json.dumps(json.loads(open(os.path.join(art, B_ARGS), 'rb').read()), indent=1).encode()   # same content, not JCS
            open(os.path.join(art, B_ARGS), 'wb').write(raw)
            ps[G3]['subject']['action']['arguments_digest'] = 'sha256:' + wr.sha256_hex(raw)
        resign(b, trust, e)
    case('X10 signed issuer: non-canonical arguments bytes', 'not canonical JSON', x10)

    def x11(b):
        def e(ps, art):
            c = claim(ps[G3], 'a2'); link(c, 'token y')['evidence'][0].update({'token': A_TOK, 'decision': 'ALLOW'})
            c['asserts'] = {'decision': 'ALLOW'}
        resign(b, trust, e)
    case('X11 signed issuer: the map link speaks of another token than the proof', 'INVALID: links disagree on token', x11)

    def x12(b):
        def e(ps, art):
            open(os.path.join(art, B_Y), 'wb').write((A_TOK).to_bytes(4, 'little'))
            c = claim(ps[G3], 'a2'); link(c, 'G computed')['evidence'][0]['token'] = A_TOK
            link(c, 'token y')['evidence'][0].update({'token': A_TOK, 'decision': 'ALLOW'}); c['asserts'] = {'decision': 'ALLOW', 'token': A_TOK}
        resign(b, trust, e)
    case('X12 signed issuer: rewrites g3\'s answer token to an ALLOW token', 'INVALID: cp_verify exit', x12)

    passed = 0
    for name, expect, fn in cases:
        d = tempfile.mkdtemp(prefix='c2t-'); b = os.path.join(d, 'bundle'); shutil.copytree(good, b)
        try:
            fn(b)
        except FileNotFoundError as e:   # e.g. a proof-free bundle: this forgery needs the proof file
            print('%-80s %s' % (name, 'NOT RUN (needs %s)' % os.path.basename(e.filename or '?'))); shutil.rmtree(d); continue
        t = os.path.join(b, 'trust.alt.json') if os.path.exists(os.path.join(b, 'trust.alt.json')) else trust
        r = subprocess.run([sys.executable, '-I', '-B', os.path.join(C1, 'c1_check.py'), b, t, judge], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        txt = r.stdout.decode()
        caught = r.returncode == 1 and expect in txt
        passed += caught
        print('%-80s %s' % (name, 'CAUGHT' if caught else 'MISSED (exit %d)\n%s' % (r.returncode, txt)))
        shutil.rmtree(d)
    print('tamper cases caught: %d of %d' % (passed, len(cases)))
    sys.exit(0 if passed == len(cases) else 1)


if __name__ == '__main__':
    main()
