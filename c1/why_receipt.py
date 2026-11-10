#!/usr/bin/env python3
"""WHY graded receipts, v0.1 (prototype, research only). Standard library only.

Primitives shared by the issuer (c1_demo.py) and the checker (c1_check.py):
  - jcs(obj): RFC 8785 canonical JSON for the subset used here (objects, arrays, strings, integers |n| < 2^53,
    true/false/null). Floats are refused, which removes JCS's only hard part (number formatting).
  - Ed25519 (RFC 8032), transcribed from the RFC's reference algorithm. It is NOT constant-time: a prototype only,
    never for production keys. It is checked against RFC 8032 test vectors by selftest().
  - DSSE v1 envelopes (the in-toto signing envelope): PAE(payloadType, payload) is what gets signed.
"""
import base64
import hashlib
import json
import os

# ---------------------------------------------------------------- RFC 8785 (JCS), restricted subset
def _jcs_str(s):
    out = ['"']
    for ch in s:
        o = ord(ch)
        if ch == '"':
            out.append('\\"')
        elif ch == '\\':
            out.append('\\\\')
        elif o < 0x20:
            out.append({8: '\\b', 9: '\\t', 10: '\\n', 12: '\\f', 13: '\\r'}.get(o, '\\u%04x' % o))
        else:
            out.append(ch)
    out.append('"')
    return ''.join(out)


def jcs(obj):
    """Canonical JSON text (str). Object members sorted by their names' UTF-16 code units."""
    if obj is None:
        return 'null'
    if obj is True:
        return 'true'
    if obj is False:
        return 'false'
    if isinstance(obj, int):
        if abs(obj) >= 2 ** 53:
            raise ValueError('integer outside the I-JSON range')
        return str(obj)
    if isinstance(obj, float):
        raise ValueError('floats are not allowed in v0.1 receipts')
    if isinstance(obj, str):
        return _jcs_str(obj)
    if isinstance(obj, (list, tuple)):
        return '[' + ','.join(jcs(v) for v in obj) + ']'
    if isinstance(obj, dict):
        for k in obj:
            if not isinstance(k, str):
                raise ValueError('object keys must be strings')
        keys = sorted(obj, key=lambda k: k.encode('utf-16-be'))
        return '{' + ','.join(_jcs_str(k) + ':' + jcs(obj[k]) for k in keys) + '}'
    raise ValueError('type not allowed: %r' % type(obj))


def jcs_bytes(obj):
    return jcs(obj).encode('utf-8')


def sha256_hex(b):
    return hashlib.sha256(b).hexdigest()


# ---------------------------------------------------------------- Ed25519 (RFC 8032, section 6 reference algorithm)
_p = 2 ** 255 - 19
_q = 2 ** 252 + 27742317777372353535851937790883648493


def _inv(x):
    return pow(x, _p - 2, _p)


_d = -121665 * _inv(121666) % _p
_sqrt_m1 = pow(2, (_p - 1) // 4, _p)


def _add(P, Q):
    A, B = (P[1] - P[0]) * (Q[1] - Q[0]) % _p, (P[1] + P[0]) * (Q[1] + Q[0]) % _p
    C, D = 2 * P[3] * Q[3] * _d % _p, 2 * P[2] * Q[2] % _p
    E, F, G, H = B - A, D - C, D + C, B + A
    return (E * F % _p, G * H % _p, F * G % _p, E * H % _p)


def _mul(s, P):
    Q = (0, 1, 1, 0)
    while s > 0:
        if s & 1:
            Q = _add(Q, P)
        P = _add(P, P)
        s >>= 1
    return Q


def _equal(P, Q):
    return (P[0] * Q[2] - Q[0] * P[2]) % _p == 0 and (P[1] * Q[2] - Q[1] * P[2]) % _p == 0


def _recover_x(y, sign):
    if y >= _p:
        return None
    x2 = (y * y - 1) * _inv(_d * y * y + 1) % _p
    if x2 == 0:
        return None if sign else 0
    x = pow(x2, (_p + 3) // 8, _p)
    if (x * x - x2) % _p != 0:
        x = x * _sqrt_m1 % _p
    if (x * x - x2) % _p != 0:
        return None
    if (x & 1) != sign:
        x = _p - x
    return x


_gy = 4 * _inv(5) % _p
_gx = _recover_x(_gy, 0)
_G = (_gx, _gy, 1, _gx * _gy % _p)


def _compress(P):
    zi = _inv(P[2])
    x, y = P[0] * zi % _p, P[1] * zi % _p
    return int.to_bytes(y | ((x & 1) << 255), 32, 'little')


def _decompress(s):
    if len(s) != 32:
        return None
    y = int.from_bytes(s, 'little')
    sign = y >> 255
    y &= (1 << 255) - 1
    x = _recover_x(y, sign)
    return None if x is None else (x, y, 1, x * y % _p)


def _expand(secret):
    if len(secret) != 32:
        raise ValueError('an Ed25519 secret key has 32 bytes')
    h = hashlib.sha512(secret).digest()
    a = int.from_bytes(h[:32], 'little')
    a &= (1 << 254) - 8
    a |= 1 << 254
    return a, h[32:]


def ed25519_public(secret):
    a, _ = _expand(secret)
    return _compress(_mul(a, _G))


def ed25519_sign(secret, msg):
    a, prefix = _expand(secret)
    A = _compress(_mul(a, _G))
    r = int.from_bytes(hashlib.sha512(prefix + msg).digest(), 'little') % _q
    Rs = _compress(_mul(r, _G))
    h = int.from_bytes(hashlib.sha512(Rs + A + msg).digest(), 'little') % _q
    return Rs + int.to_bytes((r + h * a) % _q, 32, 'little')


def ed25519_verify(public, msg, sig):
    if len(public) != 32 or len(sig) != 64:
        return False
    A = _decompress(public)
    R = _decompress(sig[:32])
    if A is None or R is None:
        return False
    s = int.from_bytes(sig[32:], 'little')
    if s >= _q:
        return False
    h = int.from_bytes(hashlib.sha512(sig[:32] + public + msg).digest(), 'little') % _q
    return _equal(_mul(s, _G), _add(R, _mul(h, A)))


def new_secret():
    return os.urandom(32)


def key_id(public):
    return 'ed25519:' + sha256_hex(public)[:32]


# ---------------------------------------------------------------- DSSE v1
PAYLOAD_TYPE = 'application/vnd.why.receipt+json;version=0.1'


def pae(payload_type, payload):
    t = payload_type.encode('utf-8')
    return b'DSSEv1 %d %s %d %s' % (len(t), t, len(payload), payload)


def envelope(payload_obj, secret, payload_type=PAYLOAD_TYPE):
    payload = jcs_bytes(payload_obj)
    pub = ed25519_public(secret)
    sig = ed25519_sign(secret, pae(payload_type, payload))
    return {'payloadType': payload_type, 'payload': base64.b64encode(payload).decode('ascii'),
            'signatures': [{'keyid': key_id(pub), 'sig': base64.b64encode(sig).decode('ascii')}]}


def open_envelope(env, keys):
    """keys: {keyid: public bytes}. Returns (payload_obj, keyid) or raises ValueError."""
    payload = base64.b64decode(env['payload'], validate=True)
    for s in env.get('signatures', []):
        pub = keys.get(s.get('keyid'))
        if pub and ed25519_verify(pub, pae(env['payloadType'], payload), base64.b64decode(s['sig'], validate=True)):
            obj = json.loads(payload.decode('utf-8'))
            if jcs_bytes(obj) != payload:
                raise ValueError('payload is not in canonical form')
            return obj, s['keyid']
    raise ValueError('no valid signature by a known key')


def envelope_digest(env):
    return 'sha256:' + sha256_hex(jcs_bytes(env))


# ---------------------------------------------------------------- self-test (RFC 8032 section 7.1, tests 1-3)
_VECTORS = [
    ('9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60',
     'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a', '',
     'e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b'),
    ('4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb',
     '3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c', '72',
     '92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00'),
    ('c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7',
     'fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025', 'af82',
     '6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a'),
]


def selftest():
    for sk, pk, msg, sig in _VECTORS:
        sk, pk, msg, sig = (bytes.fromhex(x) for x in (sk, pk, msg, sig))
        assert ed25519_public(sk) == pk, 'public key mismatch'
        assert ed25519_sign(sk, msg) == sig, 'signature mismatch'
        assert ed25519_verify(pk, msg, sig), 'verify failed'
        assert not ed25519_verify(pk, msg + b'x', sig), 'verify accepted a changed message'
    assert jcs({'b': 1, 'a': [True, None, 'x\n"']}) == '{"a":[true,null,"x\\n\\""],"b":1}'
    return 'selftest: RFC 8032 vectors 1-3 OK; JCS subset OK'


if __name__ == '__main__':
    print(selftest())
