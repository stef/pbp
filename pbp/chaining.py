#!/usr/bin/env python2
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

import pysodium as nacl, os
from SecureString import clearmem
from utils import inc_nonce
import publickey
BLOCK_SIZE = 1 << 15

class ChainingContext(object):
    def __init__(self, me, peer, basedir):
        self.me       = me
        self.peer     = peer
        self.basedir  = basedir
        self.e_in     = ('\0' * nacl.crypto_scalarmult_curve25519_BYTES)
        self.e_out    = ('\0' * nacl.crypto_scalarmult_curve25519_BYTES)
        self.out_k    = ('\0' * nacl.crypto_secretbox_KEYBYTES)
        self.in_k     = ('\0' * nacl.crypto_secretbox_KEYBYTES)
        self.in_prev  = ('\0' * nacl.crypto_secretbox_KEYBYTES)
        self.peer_pub = ('\0' * nacl.crypto_scalarmult_curve25519_BYTES)
        self.me_id = publickey.Identity(self.me, basedir=self.basedir)
        self.peer_id = publickey.Identity(self.peer, basedir=self.basedir)

    def __repr__(self):
        return "<ChaingingCtx %s:%s>" % (self.me, self.peer)

    def load(self):
        keyfdir="%s/sk/.%s" % (self.basedir, self.me)
        if not os.path.exists(keyfdir):
            os.mkdir(keyfdir)
            return self
        keyfname='%s/%s' % (keyfdir, self.peer)
        if not os.path.exists(keyfname):
            return self
        if not self.me_id:
            self.me_id = publickey.Identity(self.me, basedir=self.basedir)
        with open(keyfname,'r') as fd:
            nonce = fd.read(nacl.crypto_box_NONCEBYTES)
            plain =  nacl.crypto_box_open(fd.read(), nonce, self.me_id.cp, self.me_id.cs)
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
        keyfdir="%s/sk/.%s" % (self.basedir, self.me)
        if not os.path.exists(keyfdir):
            os.mkdir(keyfdir)
        fname='%s/%s' % (keyfdir, self.peer)
        nonce = nacl.randombytes(nacl.crypto_box_NONCEBYTES)
        ctx=''.join((self.e_in,
                     self.e_out,
                     self.peer_pub,
                     self.out_k,
                     self.in_k,
                     self.in_prev))
        if not self.me_id:
            self.me_id = publickey.Identity(self.me, basedir=self.basedir)
        with open(fname,'w') as fd:
            fd.write(nonce)
            fd.write(nacl.crypto_box(ctx, nonce, self.me_id.cp, self.me_id.cs))

    def encrypt(self,plain):
        if self.out_k == ('\0' * nacl.crypto_scalarmult_curve25519_BYTES):
            # encrypt using public key
            nonce = nacl.randombytes(nacl.crypto_box_NONCEBYTES)
            cipher= nacl.crypto_box(plain, nonce, self.peer_id.cp, self.me_id.cs)
        else:
            # encrypt using chaining mode
            nonce = nacl.randombytes(nacl.crypto_secretbox_NONCEBYTES)
            cipher = nacl.crypto_secretbox(plain, nonce, self.out_k)

        return cipher, nonce

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
        #else: # axolotlize
        #    print 'axolotl!'
        #    self.out_k = nacl.crypto_generichash(self.out_k,
        #                                         nacl.crypto_scalarmult_curve25519(self.me_id.cs, self.peer_id.cp),
        #                                         nacl.crypto_scalarmult_curve25519_BYTES)

        # compose packet
        dh1 = nacl.crypto_scalarmult_curve25519_base(self.e_out)
        dh2 = (nacl.crypto_scalarmult_curve25519_base(self.e_in)
               if self.e_in != ('\0' * nacl.crypto_scalarmult_curve25519_BYTES)
               else ('\0' * nacl.crypto_scalarmult_curve25519_BYTES))
        plain = ''.join((dh1, dh2, plain))

        # encrypt the whole packet
        return self.encrypt(plain)

    def decrypt(self, cipher, nonce):
        if self.in_k == ('\0' * nacl.crypto_scalarmult_curve25519_BYTES):
            # use pk crypto to decrypt the packet
            return nacl.crypto_box_open(cipher, nonce, self.peer_id.cp, self.me_id.cs)
        else:
            # decrypt using chained keys
            try:
                return nacl.crypto_secretbox_open(cipher, nonce, self.in_k)
            except ValueError:
                # with previous key in case a prev send failed to be delivered
                return nacl.crypto_secretbox_open(cipher, nonce, self.in_prev)

    def receive(self, cipher, nonce):
        # decrypt the packet
        plain = self.decrypt(cipher, nonce)

        # update context
        self.peer_pub=plain[:nacl.crypto_scalarmult_curve25519_BYTES]
        if self.e_out != ('\0' * nacl.crypto_scalarmult_curve25519_BYTES):
            dh2=plain[nacl.crypto_scalarmult_curve25519_BYTES:nacl.crypto_scalarmult_curve25519_BYTES*2]
            self.out_k = nacl.crypto_scalarmult_curve25519(self.e_out, dh2)
        return plain[nacl.crypto_scalarmult_curve25519_BYTES*2:]

    def clear(self):
        clearmem(self.e_in)
        self.e_in=None
        clearmem(self.e_out)
        self.e_out=None
        clearmem(self.out_k)
        self.out_k=None
        clearmem(self.in_k)
        self.in_k=None
        clearmem(self.in_prev)
        self.in_prev=None
        self.me_id.clear()

    def buffered_encrypt(self, infd,outfd):
        self.load()
        msg=infd.read(BLOCK_SIZE)
        if msg:
            cipher, nonce = self.send(msg)
            outfd.write(nonce)
            outfd.write(cipher)
            msg=infd.read(BLOCK_SIZE)
            while msg:
                nonce = inc_nonce(nonce)
                cipher, nonce = self.encrypt(msg, nonce)
                outfd.write(cipher)
                msg=infd.read(BLOCK_SIZE)
        self.save()
        self.clear()

    def buffered_decrypt(self, infd,outfd):
        self.load()
        blocklen=BLOCK_SIZE+(nacl.crypto_scalarmult_curve25519_BYTES*2)
        if self.out_k == ('\0' * nacl.crypto_scalarmult_curve25519_BYTES):
            nonce = infd.read(nacl.crypto_box_NONCEBYTES)
        else:
            nonce = infd.read(nacl.crypto_secretbox_NONCEBYTES)
        ct = infd.read(blocklen+16)
        msg = self.receive(ct,nonce)
        while ct:
            outfd.write(msg)
            nonce = inc_nonce(nonce)
            ct = infd.read(BLOCK_SIZE+16)
            if ct:
                msg = self.decrypt(ct,nonce)
        self.save()
        self.clear()
