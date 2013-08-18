#!/usr/bin/env python

import nacl
from base85 import b85encode

def _2user():
    # 1st user
    exp1 = nacl.randombytes(nacl.crypto_scalarmult_curve25519_BYTES)
    public1 = nacl.crypto_scalarmult_curve25519_base(exp1)
    #print "public1:    \t%s\nexp1:    \t%s" % (b85encode(public1), b85encode(exp1))
    print
    # 2nd user
    exp2 = nacl.randombytes(nacl.crypto_scalarmult_curve25519_BYTES)
    public2 = nacl.crypto_scalarmult_curve25519_base(exp2)
    key = nacl.crypto_scalarmult_curve25519(exp2, public1)
    print "key:    \t%s" % (b85encode(key))
    #print "public2:    \t%s\nkey:    \t%s" % (b85encode(public2), b85encode(key))
    print
    # 1st user completing DH
    key = nacl.crypto_scalarmult_curve25519(exp1, public2)
    print "key:    \t%s" % (b85encode(key))

def _3user():
    eA = nacl.randombytes(nacl.crypto_scalarmult_curve25519_BYTES)
    pA = nacl.crypto_scalarmult_curve25519_base(eA)
    print "A public:    \t%s\nA exp:    \t%s" % (b85encode(pA), b85encode(eA))

    eB = nacl.randombytes(nacl.crypto_scalarmult_curve25519_BYTES)
    pB = nacl.crypto_scalarmult_curve25519_base(eB)
    print "B public:    \t%s\nB exp:    \t%s" % (b85encode(pB), b85encode(eB))

    eC = nacl.randombytes(nacl.crypto_scalarmult_curve25519_BYTES)
    pC = nacl.crypto_scalarmult_curve25519_base(eC)
    print "C public:    \t%s\nC exp:    \t%s" % (b85encode(pC), b85encode(eC))

    print
    pAB = nacl.crypto_scalarmult_curve25519(eB, pA)
    print "public AB", b85encode(pAB)
    pBA = nacl.crypto_scalarmult_curve25519(eA, pB)
    print "public BA", b85encode(pBA)
    pCA = nacl.crypto_scalarmult_curve25519(eA, pC)
    print "public CA", b85encode(pCA)

    print
    key = nacl.crypto_scalarmult_curve25519(eB, pCA)
    print "key:    \t%s" % (b85encode(key))
    key = nacl.crypto_scalarmult_curve25519(eC, pBA)
    print "key:    \t%s" % (b85encode(key))
    key = nacl.crypto_scalarmult_curve25519(eC, pAB)
    print "key:    \t%s" % (b85encode(key))

def test():
    print '-' * 90
    print ' '*30, '2 user DH test'
    print
    _2user()

    print '-' * 90
    print ' '*30, '3 user DH test'
    print
    _3user()

    print '-' * 90
    print ' '*30, 'multi-party ECDH'
    print
    ECDH.mpecdh([ECDH() for _ in range(9)])

class ECDH:
    def __init__(self):
        self.shared = None
        self.key = nacl.randombytes(nacl.crypto_scalarmult_curve25519_BYTES)
        self.public = nacl.crypto_scalarmult_curve25519_base(self.key)

    def MPDH(self, point, i, us, other):
        #print peers.index(self), i, us, other
        if not other:
            self.finish(point)
        elif i<len(us):
            us[i].MPDH(self.addpeer(point), i+1, us, other)
        else:
            half1=other[:len(other)/2]
            half2=other[len(other)/2:]
            p=self.addpeer(point)
            if half1: half1[0].MPDH(p, 1, half1, half2 )
            if half2: half2[0].MPDH(p, 1, half2, half1 )

    def addpeer(self, point):
        return nacl.crypto_scalarmult_curve25519(self.key, point)

    def finish(self,point):
        self.shared=nacl.crypto_scalarmult_curve25519(self.key, point)
        return self.shared

    def __repr__(self):
        return str(peers.index(self))

    def __str__(self):
        return b85encode(self.shared)

    @staticmethod
    def mpecdh(peers):
        half1=peers[:len(peers)/2]
        half2=peers[len(peers)/2:]
        half1[1].MPDH(half1[0].public, 2, half1, half2)
        half2[1].MPDH(half2[0].public, 2, half2, half1)
        print '\n'.join(map(str,peers))

if __name__ == '__main__':
    print "-" * 80
    test()
