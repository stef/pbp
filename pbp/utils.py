#!/usr/bin/env python2

import struct, ctypes, sys
import pysodium as nacl

def split_by_n( seq, n ):
    """A generator to divide a sequence into chunks of n units.
       src: http://stackoverflow.com/questions/9475241/split-python-string-every-nth-character"""
    while seq:
        yield seq[:n]
        seq = seq[n:]

# pure python z85 codec - name is misleading it is not ascii85, but a variant seen here:
# http://rfc.zeromq.org/spec:32
# Copyright (C) 2008 Brendan Cully <brendan at kublai.com>,
#               2014 tlinden
#               2014 stf s@ctrlc.hu
# This software may be used and distributed according to the terms of
# the GNU General Public License, incorporated herein by reference.

_b85chars = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ.-:+=^!/*?&<>()[]{}@%$#"

_b85dec = {}

def _mkb85dec():
    for i in range(len(_b85chars)):
        _b85dec[_b85chars[i]] = i

def b85encode(text, pad=False):
    """encode text in base85 format"""
    l = len(text)
    r = l % 4
    if r:
        text += '\0' * (4 - r)
    longs = len(text) >> 2
    out = []
    words = struct.unpack('>%dL' % (longs), text)
    for word in words:
        # unrolling improved speed by 33%
        word, r = divmod(word, 85)
        e = _b85chars[r]
        word, r = divmod(word, 85)
        d = _b85chars[r]
        word, r = divmod(word, 85)
        c = _b85chars[r]
        word, r = divmod(word, 85)
        b = _b85chars[r]
        word, r = divmod(word, 85)
        a = _b85chars[r]

        out += (a, b, c, d, e)

    out = ''.join(out)
    if pad:
        return out

    # Trim padding
    olen = l % 4
    if olen:
        olen += 1
    olen += l / 4 * 5
    return out[:olen]

def b85decode(text):
    """decode base85-encoded text"""
    if not _b85dec:
        _mkb85dec()

    l = len(text)
    out = []
    for i in range(0, len(text), 5):
        chunk = text[i:i+5]
        acc = 0
        for j in range(len(chunk)):
            try:
                acc = acc * 85 + _b85dec[chunk[j]]
            except KeyError:
                raise TypeError('Bad base85 character at byte %d' % (i + j))
        if acc > 4294967295:
            raise OverflowError('Base85 overflow in hunk starting at byte %d' % i)
        out.append(acc)

    # Pad final chunk if necessary
    cl = l % 5
    if cl:
        acc *= 85 ** (5 - cl)
        if cl > 1:
            acc += 0xffffff >> (cl - 2) * 8
        out[-1] = acc

    out = struct.pack('>%dL' % (len(out)), *out)
    if cl:
        out = out[:-(5 - cl)]

    # Unpad previously zero padded input, if any
    unpadlen = len(out)
    for i in reversed(range(unpadlen)):
        if out[i] != '\0' and i < unpadlen:
            unpadlen = i + 1
            break

    return out[:unpadlen]

_MCL_CURRENT = 1
_MCL_FUTURE = 2
def lockmem():
   try:
     libc = ctypes.CDLL("libc.so.6")
   except EnvironmentError:
       print >>sys.stderr, "cannot lock memory"
       return
   if libc.mlockall(_MCL_CURRENT | _MCL_FUTURE):
       print >>sys.stderr, "cannot lock memory"

def inputfd(infile):
    if hasattr(infile, 'read'): return infile
    if not infile or infile == '-':
        return sys.stdin
    else:
        return open(infile,'r')

def outputfd(outfile):
    if hasattr(outfile, 'read'): return outfile
    if not outfile or outfile == '-':
        return sys.stdout
    else:
        return open(outfile,'w')

def inc_nonce(nonce):
    i=0
    nonce = [x for x in nonce]
    while(i<nacl.crypto_box_NONCEBYTES):
        nonce[i]=chr(ord(nonce[i])+1)
        if nonce[i]!=0: break
        i+=1
    return ''.join(nonce)

