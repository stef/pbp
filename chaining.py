#!/usr/bin/env python
# -*- coding: utf-8 -*-

#    This program is free software: you can redistribute it and/or modify it
#    under the terms of the GNU Affero General Public License as
#    published by the Free Software Foundation, either version 3 of
#    the License, or (at your option) any later version.

#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
#    Affero General Public License for more details.

#    You should have received a copy of the GNU Affero General Public
#    License along with this program. If not, see
#    <http://www.gnu.org/licenses/>.

# (C) 2013 by Stefan Marsiske, <s@ctrlc.hu>

import nacl, os
from pbp import Identity, die, defaultbase as basedir
from utils import b85encode

class ChainingContext(object):
    def __init__(self, me, peer):
        self.me       = me
        self.peer     = peer
        self.e_in     = ('\0' * nacl.crypto_scalarmult_curve25519_BYTES)
        self.e_out    = ('\0' * nacl.crypto_scalarmult_curve25519_BYTES)
        self.out_k    = ('\0' * nacl.crypto_secretbox_KEYBYTES)
        self.in_k     = ('\0' * nacl.crypto_secretbox_KEYBYTES)
        self.in_prev  = ('\0' * nacl.crypto_secretbox_KEYBYTES)
        self.peer_pub = ('\0' * nacl.crypto_scalarmult_curve25519_BYTES)

    def str(self):
        return "%s:\n\t%s" % (self.me,
                            '\n\t'.join((b85encode(self.out_k),
                                         b85encode(self.in_k),
                                         #b85encode(self.peer_pub),
                                         #b85encode(self.in_prev),
                                         #b85encode(self.e_in),
                                         #b85encode(self.e_out)
                                         )))

    def load(self):
        keyfdir="%s/sk/.%s" % (basedir, self.me)
        if not os.path.exists(keyfdir):
            os.mkdir(keyfdir)
            return self
        keyfname='%s/%s' % (keyfdir, self.peer)
        if not os.path.exists(keyfname):
            return self
        mkey = Identity(self.me, basedir=basedir)
        with open(keyfname,'r') as fd:
            nonce = fd.read(nacl.crypto_box_NONCEBYTES)
            plain =  nacl.crypto_box_open(fd.read(), nonce, mkey.cp, mkey.cs)
        c=nacl.crypto_scalarmult_curve25519_BYTES
        i=0
        self.e_in     = plain[:c]
        i+=c
        self.e_out    = plain[i:i+c]
        i+=c
        self.peer_pub = plain[i:i+c]
        i+=c
        c=nacl.crypto_secretbox_KEYBYTES
        self.out_k    = plain[i:i+c]
        i+=c
        self.in_k     = plain[i:i+c]
        i+=c
        self.in_prev  = plain[i:i+c]

    def save(self):
        fname="%s/sk/.%s/%s" % (basedir, self.me, self.peer)
        nonce = nacl.randombytes(nacl.crypto_box_NONCEBYTES)
        ctx=''.join((self.e_in,
                     self.e_out,
                     self.peer_pub,
                     self.out_k,
                     self.in_k,
                     self.in_prev))
        mkey = Identity(self.me, basedir=basedir)
        with open(fname,'w') as fd:
            fd.write(nonce)
            fd.write(nacl.crypto_box(ctx, nonce, mkey.cp, mkey.cs))

    def send(self,plain):
        # update context
        if self.peer_pub != ('\0' * nacl.crypto_scalarmult_curve25519_BYTES):
            # calculate a new incoming key, and finish that DH, start a new for
            # outgoing keys.
            # only do this directly after receiving a packet, not on later sends
            # without receiving any acks before, we reset peer_pub to signal, that
            # an incoming request has been already once processed like this.
            self.e_in = nacl.randombytes(nacl.crypto_scalarmult_curve25519_BYTES)
            self.in_prev = self.in_k
            self.in_k = nacl.crypto_scalarmult_curve25519(self.e_in, self.peer_pub)
            self.peer_pub = ('\0' * nacl.crypto_scalarmult_curve25519_BYTES)

            # generate e_out
            self.e_out = nacl.randombytes(nacl.crypto_scalarmult_curve25519_BYTES)

        elif self.out_k == ('\0' * nacl.crypto_secretbox_KEYBYTES):
            # only for the very first packet necessary
            # we explicitly need to generate e_out
            self.e_out = nacl.randombytes(nacl.crypto_scalarmult_curve25519_BYTES)

        # compose packet
        dh1 = nacl.crypto_scalarmult_curve25519_base(self.e_out)
        dh2 = (nacl.crypto_scalarmult_curve25519_base(self.e_in)
               if self.e_in != ('\0' * nacl.crypto_scalarmult_curve25519_BYTES)
               else ('\0' * nacl.crypto_scalarmult_curve25519_BYTES))
        plain = ''.join((dh1, dh2, plain))

        # encrypt the whole packet
        if self.out_k == ('\0' * nacl.crypto_scalarmult_curve25519_BYTES):
            # encrypt using public key
            nonce = nacl.randombytes(nacl.crypto_box_NONCEBYTES)
            cipher= nacl.crypto_box(plain,
                                    nonce,
                                    Identity(self.peer, basedir=basedir).cp,
                                    Identity(self.me, basedir=basedir).cs)
        else:
            # encrypt using chaining mode
            nonce = nacl.randombytes(nacl.crypto_secretbox_NONCEBYTES)
            cipher = nacl.crypto_secretbox(plain, nonce, self.out_k)

        return cipher, nonce

    def receive(self, cipher, nonce):
        # decrypt the packet
        if self.in_k == ('\0' * nacl.crypto_scalarmult_curve25519_BYTES):
            # use pk crypto to decrypt the packet
            plain = nacl.crypto_box_open(cipher,
                                         nonce,
                                         Identity(self.peer, basedir=basedir).cp,
                                         Identity(self.me, basedir=basedir).cs)
        else:
            # decrypt using chained keys
            try:
                print
                plain = nacl.crypto_secretbox_open(cipher, nonce, self.in_k)
            except ValueError:
                # with previous key in case a prev send failed to be delivered
                plain = nacl.crypto_secretbox_open(cipher, nonce, self.in_prev)

        # update context
        self.peer_pub=plain[:nacl.crypto_scalarmult_curve25519_BYTES]
        if self.e_out != ('\0' * nacl.crypto_scalarmult_curve25519_BYTES):
            dh2=plain[nacl.crypto_scalarmult_curve25519_BYTES:nacl.crypto_scalarmult_curve25519_BYTES*2]
            self.out_k = nacl.crypto_scalarmult_curve25519(self.e_out, dh2)
        return plain[nacl.crypto_scalarmult_curve25519_BYTES*2:]

def test():
    global basedir
    basedir = 'test-pbp'
    alice = ChainingContext('alice','bob')
    bob = ChainingContext('bob','alice')

    alice.load()
    bob.load()

    c,n = alice.send('howdy')
    print bob.receive(c,n)

    c,n = bob.send('howdy')
    print alice.receive(c,n)

    c,n = alice.send('howdy')
    print bob.receive(c,n)

    c,n = alice.send('howdy')
    print bob.receive(c,n)

    c,n = bob.send('howdy')
    print alice.receive(c,n)

    c,n = alice.send('howdy')
    print bob.receive(c,n)

    c,n = bob.send('howdy')
    print alice.receive(c,n)

    c,n = alice.send('howdy')
    print bob.receive(c,n)

    c,n = bob.send('howdy')
    print alice.receive(c,n)

    c,n = alice.send('howdy')
    # lose packet
    c,n = alice.send('howdy')
    print bob.receive(c,n)

    # cross send and loose packets
    c,n = bob.send('howdy')
    c,n = bob.send('howdy')
    # crossing packets
    c1,n1 = alice.send('howdy')
    print alice.receive(c,n)
    print bob.receive(c1,n1)

    # contine normal sending
    c,n = alice.send('ok')
    print bob.receive(c,n)

    bob.save()
    alice.save()

    alice1 = ChainingContext('alice','bob')
    bob1 = ChainingContext('bob','alice')

    print "testing copies"
    alice1.load()
    bob1.load()

    c,n = alice1.send('howdy')
    print bob1.receive(c,n)

    c,n = bob1.send('howdy')
    print alice1.receive(c,n)

if __name__ == '__main__':
    test()
