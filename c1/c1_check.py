#!/usr/bin/env python3
"""C1 checker: independently verifies and GRADES a bundle of WHY v0.1 receipts (research prototype).

usage: python3 -I -B c1_check.py BUNDLE_DIR TRUST_JSON JUDGE_CP_VERIFY [--json]
It trusts only TRUST_JSON (keys, commitment registry, judge sha256) and the judge binary, never the receipts' own claims.
JUDGE_CP_VERIFY may be '-' (no judge): proof links are then reported as not re-checked, never as passed.
A relative tokenizer_path in TRUST_JSON is resolved against TRUST_JSON's folder.
Exit 0: every record is valid and every claim is OK. 1: some record or claim failed. 2: usage or setup error.
3: nothing failed, but some evidence files (e.g. proofs) or the judge were absent, so some links were not re-checked.
"""
import base64, json, os, subprocess, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import why_receipt as wr
import why_encoder as we

LEVELS = ['L0', 'L1', 'L2', 'L3', 'L4', 'L5']
lv = LEVELS.index


def check_evidence(ev, art, trust, judge, claim_levels, subject=None, claim_facts=None):
    """Returns (level_int, note, facts). Unverifiable evidence gives at most L1.
    facts: what the checker itself established ({'request_sha256', 'token', 'decision'}); the links of one claim must agree on them.
    An absent evidence file (or no judge for a proof) gives L0 with a note starting 'MISSING': not re-checked, never passed."""
    try:
        return _check_evidence(ev, art, trust, judge, claim_levels, subject, claim_facts)
    except FileNotFoundError as e:
        return 0, 'MISSING: %s is not in this bundle (not re-checked)' % os.path.relpath(e.filename or '?', art), {}


def _check_evidence(ev, art, trust, judge, claim_levels, subject=None, claim_facts=None):
    k = ev.get('kind')
    if k == 'ref':
        lvl = claim_levels.get(ev.get('claim'))
        return (lvl, 'refers to %s' % ev.get('claim'), dict((claim_facts or {}).get(ev.get('claim'), {}))) if lvl is not None else (0, 'INVALID: reference to an unknown or later claim', {})
    if k == 'zk_inference':
        lvl, note = _check_simple(ev, art, trust, judge)
        facts = {'request_sha256': ev.get('request_sha256'), 'token': ev.get('token')} if lvl == 4 else {}
        return lvl, note, facts
    if k == 'encoded_request':
        return _check_encoded(ev, art, trust, subject or {})
    if k == 'decision_map':
        dm = trust.get('decision_maps', {}).get(ev.get('map'))
        if not dm:
            return 0, 'INVALID: decision map not in the trust store', {}
        got = we.decision(dm, ev.get('token'))
        if got != ev.get('decision'):
            return 0, 'INVALID: the pinned map gives %s for token %s, the receipt says %s' % (got, ev.get('token'), ev.get('decision')), {}
        return 4, 'recomputed by the checker: map %s gives %s for token %d' % (ev['map'], got, ev['token']), {'token': ev['token'], 'decision': got}
    lvl, note = _check_simple(ev, art, trust, judge)
    return lvl, note, {}


def _check_encoded(ev, art, trust, subject):
    """R = E(tool, arguments), recomputed by the checker with its own encoder and pinned tokenizer."""
    enc = trust.get('encoders', {}).get(ev.get('encoder'))
    if not enc or ev.get('encoder') != we.ENCODER_ID:
        return 0, 'INVALID: encoder %r not in the trust store or not implemented by this checker' % ev.get('encoder'), {}
    tok = we.Tokenizer(enc['tokenizer_path'])
    if tok.sha256 != enc['tokenizer_sha256']:
        return 0, 'INVALID: tokenizer file differs from the pinned sha256', {}
    ab = open(os.path.join(art, ev['arguments']), 'rb').read()
    try:
        args = json.loads(ab.decode('utf-8'))
        canonical = wr.jcs_bytes(args) == ab
    except Exception:
        canonical = False
    if not canonical:
        return 0, 'INVALID: arguments file is not canonical JSON (JCS)', {}
    action = subject.get('action', {})
    if 'sha256:' + wr.sha256_hex(ab) != action.get('arguments_digest'):
        return 0, 'INVALID: arguments file differs from the record\'s arguments_digest', {}
    if ev.get('tool') != action.get('tool'):
        return 0, 'INVALID: encoded tool %r differs from the record\'s tool %r' % (ev.get('tool'), action.get('tool')), {}
    try:
        want = we.encode_request(tok, action['tool'], args)
    except ValueError as e:
        return 0, 'INVALID: %s' % e, {}
    got = open(os.path.join(art, ev['request']), 'rb').read()
    if got != want:
        return 0, 'INVALID: the request is not E(tool, arguments) (recomputed by the checker)', {}
    if wr.sha256_hex(got) != ev.get('request_sha256'):
        return 0, 'INVALID: request digest mismatch', {}
    return 4, 'recomputed by the checker: request = E(%s, arguments) byte for byte' % action['tool'], {'request_sha256': ev['request_sha256']}


def _check_simple(ev, art, trust, judge):
    k = ev.get('kind')
    if k == 'gateway_observation':
        return 1, 'gateway assertion'
    if k == 'signed_statement':
        meta = trust['keys'].get(ev.get('keyid'))
        if not meta:
            return 0, 'INVALID: signer not in the trust store'
        if not wr.ed25519_verify(bytes.fromhex(meta['public_hex']), wr.jcs_bytes(ev['statement']), bytes.fromhex(ev['sig_hex'])):
            return 0, 'INVALID: signature does not verify'
        if 'artifact' in ev:
            got = wr.sha256_hex(open(os.path.join(art, ev['artifact']), 'rb').read())
            if got != ev['statement'].get('response_sha256'):
                return 0, 'INVALID: artifact digest differs from the signed statement'
        return 2, 'signed by %s (%s)' % (meta['role'], ev['keyid'])
    if k == 'artifact_digest':
        got = wr.sha256_hex(open(os.path.join(art, ev['artifact']), 'rb').read())
        return (2, 'digest recomputed') if got == ev.get('sha256') else (0, 'INVALID: digest mismatch')
    if k == 'zk_inference':
        cid = ev.get('commitment_id')
        if cid not in trust['commitments']:
            return 0, 'INVALID: commitment ID not in the checker\'s registry'
        p = lambda key: os.path.join(art, ev[key])
        for f, h in (('request', 'request_sha256'), ('proof', 'proof_sha256')):
            if wr.sha256_hex(open(p(f), 'rb').read()) != ev.get(h):
                return 0, 'INVALID: %s digest mismatch' % f
        y = int.from_bytes(open(p('token_file'), 'rb').read()[:4], 'little')
        if y != ev.get('token'):
            return 0, 'INVALID: token file says %d, receipt says %s' % (y, ev.get('token'))
        if judge == '-':
            return 0, 'MISSING: no judge (cp_verify) given; the proof was not re-checked'
        r = subprocess.run([judge, p('config'), p('ivk'), p('request'), p('token_file'), p('proof'), '-id', cid],
                           stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=600)
        last = r.stdout.decode('utf-8', 'replace').strip().splitlines()[-1] if r.stdout.strip() else ''
        if r.returncode == 0 and last == 'YES':
            return 4, 'cp_verify exit 0, YES (registry: %s)' % trust['commitments'][cid]
        return 0, 'INVALID: cp_verify exit %d, last line "%s"' % (r.returncode, last)
    if k == 'hardware_attestation':
        return 1, 'UNVERIFIABLE in v0.1 (no attestation verifier): counted as gateway assertion'
    return 1, 'UNVERIFIABLE: unknown evidence kind %r' % k


def main():
    if len(sys.argv) < 4:
        print(__doc__); sys.exit(2)
    bundle, trust_path, judge = sys.argv[1:4]
    trust = json.load(open(trust_path))
    for enc in trust.get('encoders', {}).values():
        if not os.path.isabs(enc['tokenizer_path']):
            enc['tokenizer_path'] = os.path.join(os.path.dirname(os.path.abspath(trust_path)), enc['tokenizer_path'])
    if judge != '-' and wr.sha256_hex(open(judge, 'rb').read()) != trust['judge_sha256']:
        print('SETUP: judge sha256 differs from the trust store'); sys.exit(2)
    any_missing = False
    keys = {kid: bytes.fromhex(m['public_hex']) for kid, m in trust['keys'].items() if m['role'] == 'gateway'}
    art = os.path.join(bundle, 'artifacts')
    ok, out, prev = True, [], None
    envs = [json.loads(l) for l in open(os.path.join(bundle, 'receipts.jsonl')) if l.strip()]
    for i, env in enumerate(envs):
        try:
            rec, kid = wr.open_envelope(env, keys)
        except Exception as e:
            ok = False; out.append('record %d: INVALID (%s)' % (i, e)); prev = wr.envelope_digest(env); continue
        chain = 'ok' if rec.get('seq') == i and rec.get('prev') == prev else 'BROKEN (seq %s, prev %s)' % (rec.get('seq'), (rec.get('prev') or 'null')[:20])
        ok &= chain == 'ok'
        out.append('record %d: signature ok (%s); chain %s; action %s %s' % (i, kid, chain, rec['subject']['action']['tool'], rec['subject']['action']['arguments_digest'][:23]))
        claim_levels, claim_facts = {}, {}
        for c in rec['claims']:
            if lv(c['declared_level']) < 5 and not c.get('why_not_higher'):
                ok = False; out.append('  %s: INVALID (why_not_higher missing)' % c['id']); continue
            link_levels, link_missing, notes, invalid, facts = [], [], [], False, {}
            for link in c['links']:
                best, bnote = 0, 'no evidence'
                for ev in link['evidence']:
                    lvl, note, f = check_evidence(ev, art, trust, judge, claim_levels, rec['subject'], claim_facts)
                    invalid |= note.startswith('INVALID')
                    for key, val in f.items():          # every link must speak of the same request, token, decision
                        if key in facts and facts[key] != val:
                            invalid = True; notes.append('INVALID: links disagree on %s (%s vs %s)' % (key, str(facts[key])[:16], str(val)[:16]))
                        facts.setdefault(key, val)
                    if lvl > best or bnote == 'no evidence':
                        best, bnote = lvl, note
                link_levels.append(best); link_missing.append(best == 0 and bnote.startswith('MISSING'))
                notes.append('%s -> %s (%s)' % (link['what'], LEVELS[best], bnote))
            verified = min(link_levels) if link_levels else 0
            # the most the claim could reach if every not-re-checked link passed: an OVERCLAIM even then stays an OVERCLAIM
            upper = min([5 if m else l for l, m in zip(link_levels, link_missing)]) if link_levels else 0
            # 'asserts': the claim's structured content (e.g. {"decision": "BLOCK"}); each value must be one the checker established
            unsupported, unsupported_keys = False, set()
            for key, val in (c.get('asserts') or {}).items():
                if key not in facts:
                    unsupported = True; unsupported_keys.add(key); notes.append('asserted %s=%s is not established by any checked link' % (key, val))
                elif facts[key] != val:
                    invalid = True; notes.append('INVALID: asserted %s=%s, the checker established %s' % (key, val, facts[key]))
            if unsupported:
                verified = 0
                if not (any(link_missing) and unsupported_keys <= {'request_sha256', 'token'}):   # only a proof link sets these
                    upper = 0
            claim_levels[c['id']] = verified
            claim_facts[c['id']] = facts
            declared = lv(c['declared_level'])
            verdict = ('INVALID' if invalid else 'OK' if declared <= verified else
                       'NOT RE-CHECKED' if any(link_missing) and declared <= upper else 'OVERCLAIM')
            ok &= verdict in ('OK', 'NOT RE-CHECKED')
            any_missing |= verdict == 'NOT RE-CHECKED'
            names = [link['what'] for link in c['links']]
            weakest = ('an asserted value no link establishes' if unsupported else
                       names[link_levels.index(verified)] if link_levels else '-')
            out.append('  %s: declared %s, verified %s -> %s; weakest link: %s' % (c['id'], c['declared_level'], LEVELS[verified], verdict, weakest))
            out.extend('      ' + n for n in notes)
        prev = wr.envelope_digest(env)
    try:
        cp, _ = wr.open_envelope(json.load(open(os.path.join(bundle, 'checkpoint.json'))), keys)
        cp_ok = cp['count'] == len(envs) and cp['head'] == prev
    except Exception as e:
        cp_ok = False
    ok &= cp_ok
    out.append('checkpoint: %s' % ('ok (count and head match)' if cp_ok else 'MISMATCH or invalid (records added, dropped or reordered)'))
    if ok and any_missing:
        out.append('RESULT: INCOMPLETE (nothing failed, but some links were not re-checked: evidence files or the judge are absent)')
        print('\n'.join(out)); sys.exit(3)
    out.append('RESULT: %s' % ('PASS' if ok else 'FAIL'))
    print('\n'.join(out))
    sys.exit(0 if ok else 1)


if __name__ == '__main__':
    main()
