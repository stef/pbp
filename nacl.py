#!/usr/bin/env python

import sodium

crypto_box_NONCEBYTES = sodium.lib.crypto_box_NONCEBYTES
crypto_box_PUBLICKEYBYTES = sodium.lib.crypto_box_PUBLICKEYBYTES
crypto_box_SECRETKEYBYTES = sodium.lib.crypto_box_SECRETKEYBYTES
crypto_box_ZEROBYTES = sodium.lib.crypto_box_ZEROBYTES
crypto_box_BOXZEROBYTES = sodium.lib.crypto_box_BOXZEROBYTES
crypto_secretbox_KEYBYTES = sodium.lib.crypto_secretbox_KEYBYTES
crypto_secretbox_NONCEBYTES = sodium.lib.crypto_secretbox_NONCEBYTES
crypto_secretbox_KEYBYTES = sodium.lib.crypto_secretbox_KEYBYTES
crypto_secretbox_ZEROBYTES = sodium.lib.crypto_box_ZEROBYTES
crypto_secretbox_BOXZEROBYTES = sodium.lib.crypto_box_BOXZEROBYTES
crypto_sign_PUBLICKEYBYTES = sodium.lib.crypto_sign_PUBLICKEYBYTES
crypto_sign_SECRETKEYBYTES = sodium.lib.crypto_sign_SECRETKEYBYTES
crypto_stream_KEYBYTES = sodium.lib.crypto_stream_KEYBYTES
crypto_stream_NONCEBYTES = sodium.lib.crypto_stream_NONCEBYTES
crypto_hash_BYTES = sodium.lib.crypto_hash_BYTES
crypto_scalarmult_curve25519_BYTES = sodium.lib.crypto_scalarmult_curve25519_BYTES
crypto_scalarmult_BYTES = sodium.lib.crypto_scalarmult_curve25519_BYTES
crypto_sign_BYTES = sodium.lib.crypto_sign_BYTES

def crypto_scalarmult_curve25519(n,p):
    buf = sodium.ffi.new("unsigned char[]", crypto_hash_BYTES)
    sodium.lib.crypto_scalarmult_curve25519(buf, n, p)
    return sodium.ffi.buffer(buf, crypto_scalarmult_BYTES)[:]

def crypto_scalarmult_curve25519_base(n):
    buf = sodium.ffi.new("unsigned char[]", crypto_hash_BYTES)
    sodium.lib.crypto_scalarmult_curve25519_base(buf, n)
    return sodium.ffi.buffer(buf, crypto_scalarmult_BYTES)[:]

def crypto_hash_sha256(m):
    buf = sodium.ffi.new("unsigned char[]", crypto_hash_BYTES)
    sodium.lib.crypto_hash_sha256(buf, m, len(m))
    return sodium.ffi.buffer(buf, crypto_hash_BYTES)[:]

def crypto_hash_sha512(m):
    buf = sodium.ffi.new("unsigned char[]", crypto_hash_BYTES)
    sodium.lib.crypto_hash_sha512(buf, m, len(m))
    return sodium.ffi.buffer(buf, crypto_hash_BYTES)[:]

def randombytes(l):
    buf = sodium.ffi.new("unsigned char[]", l)
    sodium.lib.randombytes(buf, l)
    return sodium.ffi.buffer(buf, l)[:]

def crypto_box_keypair():
    pk = sodium.ffi.new("unsigned char[]", crypto_box_PUBLICKEYBYTES)
    sk = sodium.ffi.new("unsigned char[]", crypto_box_SECRETKEYBYTES)
    if not sodium.lib.crypto_box_keypair(pk, sk):
        raise ValueError
    pk = sodium.ffi.buffer(pk, crypto_box_PUBLICKEYBYTES)[:]
    sk = sodium.ffi.buffer(sk, crypto_box_SECRETKEYBYTES)[:]
    return (pk, sk)

def crypto_box(msg, nonce, pk, sk):
    if None in (msg, nonce, pk, sk): raise ValueError
    padded = b"\x00" * crypto_box_ZEROBYTES + msg
    c = sodium.ffi.new("unsigned char[]", len(padded))
    if not sodium.lib.crypto_box(c, padded, len(padded), nonce, pk, sk):
        raise ValueError
    return sodium.ffi.buffer(c, len(padded))[crypto_box_BOXZEROBYTES:]

def crypto_box_open(c, nonce, pk, sk):
    if None in (c, nonce, pk, sk): raise ValueError
    padded = b"\x00" * crypto_box_BOXZEROBYTES + c
    msg = sodium.ffi.new("unsigned char[]", len(padded))
    if not sodium.lib.crypto_box_open(msg, padded, len(padded), nonce, pk, sk):
        raise ValueError
    return sodium.ffi.buffer(msg, len(padded))[crypto_box_ZEROBYTES:]

def crypto_secretbox(msg, nonce, k):
    if None in (msg, nonce, k): raise ValueError
    padded = b"\x00" * crypto_secretbox_ZEROBYTES + msg
    c = sodium.ffi.new("unsigned char[]", len(padded))
    if not sodium.lib.crypto_secretbox(c, padded, len(padded), nonce, k):
        raise ValueError
    return sodium.ffi.buffer(c, len(padded))[crypto_secretbox_BOXZEROBYTES:]

def crypto_secretbox_open(c, nonce, k):
    if None in (c, nonce, k): raise ValueError
    padded = b"\x00" * crypto_secretbox_BOXZEROBYTES + c
    msg = sodium.ffi.new("unsigned char[]", len(padded))
    if not sodium.lib.crypto_secretbox_open(msg, padded, len(padded), nonce, k):
        raise ValueError
    return sodium.ffi.buffer(msg, len(padded))[crypto_secretbox_ZEROBYTES:]

def crypto_sign_keypair():
    pk = sodium.ffi.new("unsigned char[]", crypto_sign_PUBLICKEYBYTES)
    sk = sodium.ffi.new("unsigned char[]", crypto_sign_SECRETKEYBYTES)
    if not sodium.lib.crypto_sign_keypair(pk, sk):
        raise ValueError
    pk = sodium.ffi.buffer(pk, crypto_sign_PUBLICKEYBYTES)[:]
    sk = sodium.ffi.buffer(sk, crypto_sign_SECRETKEYBYTES)[:]
    return (pk, sk)

def crypto_sign(m, sk):
    if None in (m, sk): raise ValueError
    smsg = sodium.ffi.new("unsigned char[]", len(m)+crypto_sign_BYTES)
    smsglen = sodium.ffi.new("unsigned long long *")
    if not sodium.lib.crypto_sign(smsg, smsglen, m, len(m), sk):
        raise ValueError
    return sodium.ffi.buffer(smsg, smsglen[0])[:]

def crypto_sign_open(sm, pk):
    if None in (sm, pk): raise ValueError
    msg = sodium.ffi.new("unsigned char[]", len(sm))
    msglen = sodium.ffi.new("unsigned long long *")
    if not sodium.lib.crypto_sign_open(msg, msglen, sm, len(sm), pk):
        raise ValueError
    return sodium.ffi.buffer(msg, msglen[0])[:]

def test():
    pk, sk = crypto_box_keypair()
    n = randombytes(crypto_box_NONCEBYTES)
    c = crypto_box("howdy", n, pk, sk)
    print crypto_box_open(c, n, pk, sk)

    k = randombytes(crypto_secretbox_KEYBYTES)
    n = randombytes(crypto_secretbox_NONCEBYTES)
    c = crypto_secretbox("howdy", n, k)
    print crypto_secretbox_open(c, n, k)

    print repr(crypto_hash_sha512('howdy'))
    print repr(crypto_hash_sha256('howdy'))

    s = crypto_scalarmult_curve25519_base(randombytes(crypto_scalarmult_BYTES))
    r = crypto_scalarmult_curve25519_base(randombytes(crypto_scalarmult_BYTES))
    print 'scalarmult'
    print repr(crypto_scalarmult_curve25519(s,r))

    pk, sk = crypto_sign_keypair()
    signed = crypto_sign('howdy',sk)
    print crypto_sign_open(signed, pk)

if __name__ == '__main__':
    test()
