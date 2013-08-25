#!/usr/bin/env python
# -*- coding: utf-8 -*-

from tempfile import mkdtemp
from shutil import rmtree
import unittest, pbp, os, re, identity

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
        self.assertEquals(list(identity.get_public_keys(basedir=self.pbp_path)), [])
        i = self.gen_key()
        pkeys = list(identity.get_public_keys(basedir=self.pbp_path))
        self.assertEquals(len(pkeys), 1)
        # TODO add public key and query again

    def test_getskeys(self):
        self.assertEquals(list(identity.get_secret_keys(basedir=self.pbp_path)), [])
        i = self.gen_key()
        skeys = list(identity.get_secret_keys(basedir=self.pbp_path))
        self.assertEquals(len(skeys), 1)
        # self.assertEquals(skeys, [i]) doesn't it match:
        # because identity loads keys dynamicly

    #def test_encrypt_sym_stream_pwprompt_fail(self):
    #    encrypted = pbp.encrypt(MESSAGE, pwd=OTHER_PW, stream=True)
    #    decrypted = pbp.decrypt(encrypted, basedir=self.pbp_path)
    #    self.assertNotEquals(decrypted, MESSAGE)

    def test_encrypt_sym_pwprompt_fail(self):
        encrypted = pbp.encrypt(MESSAGE, pwd=OTHER_PW)
        with self.assertRaises(ValueError):
            pbp.decrypt(encrypted, pwd='asdf')

    #def test_encrypt_sym_stream_fail(self):
    #    encrypted = pbp.encrypt(MESSAGE, pwd=OTHER_PW, stream=True)
    #    decrypted = pbp.decrypt(encrypted, pwd=PASSWORD, basedir=self.pbp_path)
    #    self.assertNotEquals(decrypted, MESSAGE)

    def test_encrypt_sym_fail(self):
        encrypted = pbp.encrypt(MESSAGE, pwd=OTHER_PW)
        with self.assertRaises(ValueError):
            pbp.decrypt(encrypted, pwd=PASSWORD, basedir=self.pbp_path)

    #def test_encrypt_sym_stream_pwprompt(self):
    #    encrypted = pbp.encrypt(MESSAGE, pwd=PASSWORD, stream=True)
    #    decrypted = pbp.decrypt(encrypted, basedir=self.pbp_path)
    #    self.assertEquals(decrypted, MESSAGE)

    def test_encrypt_sym_pwprompt(self):
        encrypted = pbp.encrypt(MESSAGE, pwd=PASSWORD)
        decrypted = pbp.decrypt(encrypted, basedir=self.pbp_path)
        self.assertEquals(decrypted, MESSAGE)

    #def test_encrypt_sym_stream(self):
    #    encrypted = pbp.encrypt(MESSAGE, pwd=PASSWORD, stream=True)
    #    decrypted = pbp.decrypt(encrypted, pwd=PASSWORD, basedir=self.pbp_path)
    #    self.assertEquals(decrypted, MESSAGE)

    def test_encrypt_sym(self):
        encrypted = pbp.encrypt(MESSAGE, pwd=PASSWORD)
        decrypted = pbp.decrypt(encrypted, pwd=PASSWORD, basedir=self.pbp_path)
        self.assertEquals(decrypted, MESSAGE)

    def test_encrypt_recipient(self):
        self_key = self.gen_key()
        rcpt_key = self.gen_key()
        encrypted = self_key.encrypt(MESSAGE, recipients=[rcpt_key])
        for key in (rcpt_key, self_key):
            decrypted = rcpt_key.decrypt(encrypted)
            self.assertEquals(decrypted[1], MESSAGE)

    def test_encrypt_recipient_no_key(self):
        self_key = self.gen_key()
        rcpt_key = self.gen_key()
        other_key = self.gen_key()
        encrypted = self_key.encrypt(MESSAGE, recipients=[rcpt_key])
        self.assertTrue(other_key.decrypt(encrypted) is None)

    def test_sign_fail(self):
        self_key = self.gen_key()
        signed = self_key.sign(MESSAGE)
        malformed = ''.join(chr(ord(c) ^ 42) for c in signed)
        self.assertTrue(identity.verify(malformed, basedir=self.pbp_path) is None)

    def test_sign_no_key(self):
        self_key = self.gen_key()
        signed = self_key.sign(MESSAGE)
        rmtree(self.pbp_path)
        self.gen_key()
        self.assertTrue(identity.verify(signed, basedir=self.pbp_path) is None)

    def test_sign(self):
        self_key = self.gen_key()
        self.assertTrue(identity.verify(self_key.sign(MESSAGE),
            basedir=self.pbp_path) is not None)

    def test_sign_master(self):
        self_key = self.gen_key()
        self.assertTrue(identity.verify(self_key.sign(MESSAGE, master=True),
            basedir=self.pbp_path, master=True) is not None)

    def tearDown(self):
        rmtree(self.tmp_dir)

    def gen_key(self):
        self.numkeys += 1
        return identity.Identity(NAME + str(self.numkeys), basedir=self.pbp_path, create=True)

if __name__ == '__main__':
    unittest.main()
