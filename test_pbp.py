#!/usr/bin/env python
# -*- coding: utf-8 -*-

from tempfile import mkdtemp
from shutil import rmtree
import unittest, pbp, os, re

NAME = "keyname"
MESSAGE = "Hello, world"
PASSWORD = "foo"
OTHER_PW = "bar"
pbp.getpass.getpass = lambda x: PASSWORD

class TestPBP(unittest.TestCase):
    numkeys = 0

    def setUp(self):
        self.tmp_dir = mkdtemp('pbp_test_pbp')
        self.pbp_path = os.path.join(self.tmp_dir, 'pbp_dir')

    def test_keyid(self):
        i = self.gen_key()
        self.assertTrue(re.match(r'^[0-9a-f]{4}(?: [0-9a-f]{4}){7}$', i.keyid()))

    def test_repr(self):
        i = self.gen_key()
        self.assertTrue(repr(i).startswith("name: " + NAME))

    def test_getpkeys(self):
        self.assertEquals(list(pbp.getpkeys(basedir=self.pbp_path)), [])
        i = self.gen_key()
        pkeys = list(pbp.getpkeys(basedir=self.pbp_path))
        self.assertEquals(len(pkeys), 1)
        # TODO add public key and query again

    def test_getskeys(self):
        self.assertEquals(list(pbp.getskeys(basedir=self.pbp_path)), [])
        i = self.gen_key()
        skeys = list(pbp.getskeys(basedir=self.pbp_path))
        self.assertEquals(len(skeys), 1)
        # TODO why doesn't it match: self.assertEquals(skeys, [i])

    def test_encrypt_sym_stream_pwprompt_fail(self):
        encrypted = pbp.encrypt(MESSAGE, pwd=OTHER_PW, stream=True)
        decrypted = pbp.decrypt(encrypted, basedir=self.pbp_path)
        self.assertNotEquals(decrypted, MESSAGE)

    def test_encrypt_sym_pwprompt_fail(self):
        encrypted = pbp.encrypt(MESSAGE, pwd=OTHER_PW)
        with self.assertRaises(ValueError):
            pbp.decrypt(encrypted, basedir=self.pbp_path)

    def test_encrypt_sym_stream_fail(self):
        encrypted = pbp.encrypt(MESSAGE, pwd=OTHER_PW, stream=True)
        decrypted = pbp.decrypt(encrypted, pwd=PASSWORD, basedir=self.pbp_path)
        self.assertNotEquals(decrypted, MESSAGE)

    def test_encrypt_sym_fail(self):
        encrypted = pbp.encrypt(MESSAGE, pwd=OTHER_PW)
        with self.assertRaises(ValueError):
            pbp.decrypt(encrypted, pwd=PASSWORD, basedir=self.pbp_path)

    def test_encrypt_sym_stream_pwprompt(self):
        encrypted = pbp.encrypt(MESSAGE, pwd=PASSWORD, stream=True)
        decrypted = pbp.decrypt(encrypted, basedir=self.pbp_path)
        self.assertEquals(decrypted, MESSAGE)

    def test_encrypt_sym_pwprompt(self):
        encrypted = pbp.encrypt(MESSAGE, pwd=PASSWORD)
        decrypted = pbp.decrypt(encrypted, basedir=self.pbp_path)
        self.assertEquals(decrypted, MESSAGE)

    def test_encrypt_sym_stream(self):
        encrypted = pbp.encrypt(MESSAGE, pwd=PASSWORD, stream=True)
        decrypted = pbp.decrypt(encrypted, pwd=PASSWORD, basedir=self.pbp_path)
        self.assertEquals(decrypted, MESSAGE)

    def test_encrypt_sym(self):
        encrypted = pbp.encrypt(MESSAGE, pwd=PASSWORD)
        decrypted = pbp.decrypt(encrypted, pwd=PASSWORD, basedir=self.pbp_path)
        self.assertEquals(decrypted, MESSAGE)

    def test_encrypt_recipient(self):
        self_key = self.gen_key()
        rcpt_key = self.gen_key()
        encrypted = pbp.encrypt(MESSAGE, recipients=[rcpt_key], self=self_key)
        for key in (rcpt_key, self_key):
            decrypted = pbp.decrypt(encrypted, basedir=self.pbp_path, self=key)
            self.assertEquals(decrypted[1], MESSAGE)

    def test_encrypt_recipient_no_key(self):
        self_key = self.gen_key()
        rcpt_key = self.gen_key()
        other_key = self.gen_key()
        encrypted = pbp.encrypt(MESSAGE, recipients=[rcpt_key], self=self_key)
        with self.assertRaises(ValueError):
            pbp.decrypt(encrypted, basedir=self.pbp_path, self=other_key)

    def test_sign_fail(self):
        self_key = self.gen_key()
        signed = pbp.sign(MESSAGE, self=self_key)
        malformed = ''.join(chr(ord(c) ^ 42) for c in signed)
        self.assertTrue(pbp.verify(malformed, basedir=self.pbp_path) is None)

    def test_sign_no_key(self):
        self_key = self.gen_key()
        signed = pbp.sign(MESSAGE, self=self_key)
        rmtree(self.pbp_path)
        self.gen_key()
        self.assertTrue(pbp.verify(signed, basedir=self.pbp_path) is None)

    def test_sign(self):
        self_key = self.gen_key()
        self.assertTrue(pbp.verify(pbp.sign(MESSAGE, self=self_key),
            basedir=self.pbp_path) is not None)

    def test_sign_master(self):
        self_key = self.gen_key()
        self.assertTrue(pbp.verify(pbp.sign(MESSAGE, self=self_key, master=True),
            basedir=self.pbp_path, master=True) is not None)

    def tearDown(self):
        rmtree(self.tmp_dir)

    def gen_key(self):
        self.numkeys += 1
        return pbp.Identity(NAME + str(self.numkeys), basedir=self.pbp_path, create=True)

if __name__ == '__main__':
    unittest.main()
