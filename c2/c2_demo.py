#!/usr/bin/env python3
"""C2a demo issuer: WHY receipts for four guarded tool calls (synthetic), each with a claim
"committed guard model G decided D for THIS call", carried to L4 by three checkable links:
  1. G computed token y on request R           (zk_inference: the checker re-runs the pristine cp_verify)
  2. R = E(tool, arguments) of this call       (encoded_request: the checker recomputes the public encoder E)
  3. token y means D under the pinned map      (decision_map: the checker recomputes the map)
usage: python3 -I -B c2_demo.py BUNDLE_DIR RUN_DIR PREP_DIR TOKENIZER JUDGE
Keys are fresh demo keys; secret keys are not written anywhere.
"""
import hashlib, json, os, shutil, sys, time
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, '..', 'c1'))
import why_receipt as wr
import why_encoder as we

# Fail-closed decision map, v0.2. CHOSEN AFTER SEEING the float model's next tokens for these four calls (the a-priori
# word list, v0.1, was empty: tok512 has no whole-word token for any of its words). A mechanism demo, not a guard.
DMAP = {'id': 'why.decision-map/ts260k-failclosed-0.2', 'allow': [13], 'default': 'BLOCK',
        'note': 'ALLOW only if the next token is a line end (<0x0A>), otherwise BLOCK. Chosen after seeing the outputs; demo only.'}


def main():
    global DMAP
    bundle, run, prep, tokp, judge = sys.argv[1:6]
    if len(sys.argv) > 6:                          # C2b: the trained guard's map
        DMAP = json.load(open(sys.argv[6]))
    gdesc = sys.argv[7] if len(sys.argv) > 7 else 'guard G = TinyStories260K (FlashProve-L4 integer conversion), committed on the RTX 5070 Ti (C2a run c2-1)'
    gname = sys.argv[8] if len(sys.argv) > 8 else 'G is TinyStories260K, a story model: this shows the binding mechanism, not a useful guard.'
    tok = we.Tokenizer(tokp)
    calls = json.load(open(os.path.join(prep, 'calls.json')))
    os.makedirs(bundle)
    art = os.path.join(bundle, 'artifacts'); os.makedirs(os.path.join(art, 'args'))
    shutil.copytree(os.path.join(run, 'config'), os.path.join(art, 'fp', 'config'))
    shutil.copytree(os.path.join(run, 'ivk'), os.path.join(art, 'fp', 'ivk'))
    cid = [l.split(':', 1)[1].strip() for l in open(os.path.join(run, 'cp_commit.log'), errors='replace') if l.startswith('commitment ID:')][0]
    fsha = lambda rel: wr.sha256_hex(open(os.path.join(art, rel), 'rb').read())
    gw = wr.new_secret(); gw_pub = wr.ed25519_public(gw)
    session = 'c2-guard-session-%d' % int(time.time())
    payloads, summary = [], []
    for c in calls:
        n, tool, args = c['name'], c['tool'], c['arguments']
        src = os.path.join(run, 'in', n + '.req')
        shutil.copy(src if os.path.exists(src) else os.path.join(run, 'reqs', n + '.req'), os.path.join(art, 'fp', n + '.req'))
        shutil.copy(os.path.join(run, 'out-' + n, n + '.y'), os.path.join(art, 'fp', n + '.y'))
        shutil.copy(os.path.join(run, 'out-' + n, n + '.proof'), os.path.join(art, 'fp', n + '.proof'))
        open(os.path.join(art, 'args', n + '.json'), 'wb').write(wr.jcs_bytes(args))
        y = int.from_bytes(open(os.path.join(art, 'fp', n + '.y'), 'rb').read()[:4], 'little')
        d = we.decision(DMAP, y)
        summary.append((n, tool, y, d))
        payloads.append({'subject': {'agent': 'demo-agent', 'session': session,
                                     'action': {'tool': tool, 'arguments_digest': 'sha256:' + wr.sha256_hex(wr.jcs_bytes(args))}},
                         'claims': [
            {'id': 'a1', 'statement': 'The gateway observed the agent request %s with these arguments.' % tool,
             'declared_level': 'L1', 'why_not_higher': 'Only the gateway saw the request.',
             'links': [{'what': 'call observed', 'evidence': [{'kind': 'gateway_observation'}]}]},
            {'id': 'a2', 'statement': 'Committed guard model G (registry) decided %s for THIS call (its tool and arguments).' % d,
             'asserts': {'decision': d, 'token': y},
             'declared_level': 'L4',
             'why_not_higher': 'L5 would need independent evidence that the decision is right. ' + gname,
             'links': [
                 {'what': 'G computed token y on request R', 'evidence': [
                     {'kind': 'zk_inference', 'system': 'FlashProve 0.16.0 (9e2bdd8f), production build, RTX 5070 Ti', 'commitment_id': cid,
                      'config': 'fp/config', 'ivk': 'fp/ivk', 'request': 'fp/%s.req' % n, 'request_sha256': fsha('fp/%s.req' % n),
                      'token_file': 'fp/%s.y' % n, 'token': y, 'proof': 'fp/%s.proof' % n, 'proof_sha256': fsha('fp/%s.proof' % n)}]},
                 {'what': 'R = E(tool, arguments) of this call', 'evidence': [
                     {'kind': 'encoded_request', 'encoder': we.ENCODER_ID, 'tool': tool, 'arguments': 'args/%s.json' % n,
                      'request': 'fp/%s.req' % n, 'request_sha256': fsha('fp/%s.req' % n)}]},
                 {'what': 'token y means the decision under the pinned map', 'evidence': [
                     {'kind': 'decision_map', 'map': DMAP['id'], 'token': y, 'decision': d}]}]},
            {'id': 'a3', 'statement': 'The gateway %s the call accordingly.' % ('forwarded' if d == 'ALLOW' else 'blocked'),
             'declared_level': 'L1', 'why_not_higher': 'Enforcement is the gateway\'s own word; nothing third-party observes it.',
             'links': [{'what': 'decision enforced', 'evidence': [{'kind': 'gateway_observation'}]}]}]})
    lines, prev = [], None
    for seq, p in enumerate(payloads):
        p.update({'schema': 'why.receipt/0.1', 'seq': seq, 'prev': prev, 'issued_at': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())})
        env = wr.envelope(p, gw); lines.append(env); prev = wr.envelope_digest(env)
    with open(os.path.join(bundle, 'receipts.jsonl'), 'w') as f:
        for env in lines:
            f.write(wr.jcs(env) + '\n')
    cp = {'schema': 'why.checkpoint/0.1', 'session': session, 'count': len(lines), 'head': prev}
    json.dump(wr.envelope(cp, gw, 'application/vnd.why.checkpoint+json;version=0.1'), open(os.path.join(bundle, 'checkpoint.json'), 'w'))
    trust = {'keys': {wr.key_id(gw_pub): {'role': 'gateway', 'public_hex': gw_pub.hex()}},
             'commitments': {cid: gdesc},
             'encoders': {we.ENCODER_ID: {'tokenizer_path': os.path.abspath(tokp), 'tokenizer_sha256': tok.sha256, 'template': we.TEMPLATE}},
             'decision_maps': {DMAP['id']: DMAP},
             'judge_sha256': hashlib.sha256(open(judge, 'rb').read()).hexdigest()}
    json.dump(trust, open(os.path.join(bundle, '..', 'trust.json'), 'w'), indent=1)
    for s in summary:
        print('%s %-12s proved token %3d -> %s' % s)
    print('wrote %d receipts + checkpoint to %s; trust.json beside it (out of band)' % (len(lines), bundle))


if __name__ == '__main__':
    main()
