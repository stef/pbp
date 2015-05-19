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

import pysodium as nacl, os, sys
import publickey
from utils import b85encode, split_by_n

class MPECDH():
    def __init__(self, id, me = None, peers = None, basedir = None):
        self.peers = peers
        self.id = id
        self.key = None
        self.me = me
        self.basedir = basedir
        self.me_id = None

    def save(self):
        keyfdir="%s/dh/" % (self.basedir)
        if not os.path.exists(keyfdir):
            os.mkdir(keyfdir)
        keyfdir="%s/%s" % (keyfdir, self.me)
        if not os.path.exists(keyfdir):
            os.mkdir(keyfdir)
        fname='%s/%s' % (keyfdir, self.id)
        nonce = nacl.randombytes(nacl.crypto_box_NONCEBYTES)
        if not self.me_id:
            self.me_id = publickey.Identity(self.me, basedir=self.basedir)
        with open(fname,'w') as fd:
            fd.write(nonce)
            fd.write(nacl.crypto_box(self.key, nonce, self.me_id.cp, self.me_id.cs))

    def load(self):
        keyfname="%s/dh/%s/%s" % (self.basedir, self.me, self.id)
        if not self.me_id:
            self.me_id = publickey.Identity(self.me, basedir=self.basedir)
        with open(keyfname,'r') as fd:
            nonce = fd.read(nacl.crypto_box_NONCEBYTES)
            raw = fd.read()
            self.key =  nacl.crypto_box_open(raw, nonce, self.me_id.cp, self.me_id.cs)
        os.remove(keyfname)

    def mpecdh1(self, keyring = []):
        self.key = nacl.randombytes(nacl.crypto_scalarmult_curve25519_BYTES)
        keyring = [nacl.crypto_scalarmult_curve25519(self.key, public)
                   for public in keyring]
        keyring.append(nacl.crypto_scalarmult_curve25519_base(self.key))
        if len(keyring) == int(self.peers): # we are last, remove our own secret
            self.secret = keyring[0]
            keyring = keyring[1:]
        return keyring

    def mpecdh2(self, keyring):
        self.secret = nacl.crypto_scalarmult_curve25519(self.key, keyring[0])
        keyring = [nacl.crypto_scalarmult_curve25519(self.key, public)
                   for public in keyring[1:]]
        return keyring

def load_dh_keychain(infile):
    if not infile or infile == '-':
        fd = sys.stdin
    else:
        fd = open(infile,'r')
    keychain = list(split_by_n(fd.read(), nacl.crypto_scalarmult_curve25519_BYTES))
    if fd != sys.stdin: fd.close()
    return keychain

def save_dh_keychain(outfile, keychain):
    if not outfile or outfile == '-':
        fd = sys.stdout
    else:
        fd = open(outfile,'w')
    fd.write(''.join(keychain))
