#!/usr/bin/env python2
# -*- coding: utf-8 -*-

from tempfile import mkdtemp
from shutil import rmtree
import unittest, pbp, os, re
from pbp import pbp, publickey

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
        self.assertEquals(list(publickey.get_public_keys(basedir=self.pbp_path)), [])
        i = self.gen_key()
        pkeys = list(publickey.get_public_keys(basedir=self.pbp_path))
        self.assertEquals(len(pkeys), 1)
        # TODO add public key and query again

    def test_getskeys(self):
        self.assertEquals(list(publickey.get_secret_keys(basedir=self.pbp_path)), [])
        i = self.gen_key()
        skeys = list(publickey.get_secret_keys(basedir=self.pbp_path))
        self.assertEquals(len(skeys), 1)
        # self.assertEquals(skeys, [i]) doesn't it match:
        # because identity loads keys dynamicly

    def test_encrypt_sym_pwprompt_fail(self):
        encrypted = pbp.encrypt(MESSAGE, pwd=OTHER_PW)
        self.assertTrue(pbp.decrypt(encrypted, pwd='asdf') is None)

    def test_encrypt_sym_fail(self):
        encrypted = pbp.encrypt(MESSAGE, pwd=OTHER_PW)
        self.assertTrue(pbp.decrypt(encrypted, pwd=PASSWORD) is None)

    def test_encrypt_sym_pwprompt(self):
        encrypted = pbp.encrypt(MESSAGE, pwd=PASSWORD)
        decrypted = pbp.decrypt(encrypted)
        self.assertEquals(decrypted, MESSAGE)

    def test_encrypt_sym(self):
        encrypted = pbp.encrypt(MESSAGE, pwd=PASSWORD)
        decrypted = pbp.decrypt(encrypted, pwd=PASSWORD)
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
        self.assertTrue(publickey.verify(malformed, basedir=self.pbp_path) is None)

    def test_sign_no_key(self):
        self_key = self.gen_key()
        signed = self_key.sign(MESSAGE)
        rmtree(self.pbp_path)
        self.gen_key()
        self.assertTrue(publickey.verify(signed, basedir=self.pbp_path) is None)

    def test_sign(self):
        self_key = self.gen_key()
        self.assertTrue(publickey.verify(self_key.sign(MESSAGE),
            basedir=self.pbp_path) is not None)

    def test_sign_master(self):
        self_key = self.gen_key()
        self.assertTrue(publickey.verify(self_key.sign(MESSAGE, master=True),
            basedir=self.pbp_path, master=True) is not None)

    def test_simple_dh(self):
        (exp,pub1) = pbp.dh1_handler()
        (pub2,secret) = pbp.dh2_handler(pub1)
        self.assertEquals(pbp.dh3_handler(pub2,exp), secret)

    def test_mpecdh(self):
        publickey.Identity('alice', basedir=self.pbp_path, create=True)
        publickey.Identity('bob', basedir=self.pbp_path, create=True)
        publickey.Identity('carol', basedir=self.pbp_path, create=True)
        pbp.mpecdh_start_handler('1st', 3, 'alice', '/dev/null', self.tmp_dir+ '/step1', basedir=self.pbp_path)
        pbp.mpecdh_start_handler('1st', 3, 'bob', self.tmp_dir+'/step1', self.tmp_dir+'/step2', basedir=self.pbp_path)
        s1=pbp.mpecdh_start_handler('1st', 3, 'carol', self.tmp_dir+'/step2', self.tmp_dir+'/step3', basedir=self.pbp_path)
        s2=pbp.mpecdh_end_handler('1st', 'alice', self.tmp_dir+'/step3', self.tmp_dir+'/step4', basedir=self.pbp_path)
        s3=pbp.mpecdh_end_handler('1st', 'bob', self.tmp_dir+'/step4', self.tmp_dir+'/step5', basedir=self.pbp_path)
        self.assertEquals(s1,s2)
        self.assertEquals(s2,s3)

    def test_chaining(self):
        publickey.Identity('alice', basedir=self.pbp_path, create=True)
        publickey.Identity('bob', basedir=self.pbp_path, create=True)
        msg=self.tmp_dir+'/msg'
        msg2=self.tmp_dir+'/msg2'
        msg3=self.tmp_dir+'/msg3'
        msg4=self.tmp_dir+'/msg4'
        ct=self.tmp_dir+'/ct'
        ct2=self.tmp_dir+'/ct2'
        ct3=self.tmp_dir+'/ct3'
        with open(msg, 'w') as fd:
            fd.write('0' * 1080)

        pbp.chaining_encrypt_handler(infile=msg, outfile=ct, recipient='bob', self='alice', basedir=self.pbp_path)
        pbp.chaining_decrypt_handler(infile=ct, outfile=msg2, recipient='bob', self='alice', basedir=self.pbp_path)

        with open(msg2, 'r') as fd:
            res = fd.read()
        self.assertEquals(res, '0'*1080)

        with open(msg, 'w') as fd:
            fd.write('1' * 1080)

        pbp.chaining_encrypt_handler(infile=msg, outfile=ct2, recipient='alice', self='bob', basedir=self.pbp_path)
        pbp.chaining_decrypt_handler(infile=ct2, outfile=msg3, recipient='alice', self='bob', basedir=self.pbp_path)

        with open(msg3, 'r') as fd:
            res = fd.read()
        self.assertEquals(res, '1'*1080)

        #with open(msg, 'w') as fd:
        #    fd.write('2' * 1080)

        #pbp.chaining_encrypt_handler(infile=msg, outfile=ct3, recipient='bob', self='alice', basedir=self.pbp_path)
        #pbp.chaining_decrypt_handler(infile=ct3, outfile=msg4, recipient='bob', self='alice', basedir=self.pbp_path)

        #with open(msg4, 'r') as fd:
        #    res = fd.read()
        #self.assertEquals(res, '2'*1080)

    def test_crypt(self):
        publickey.Identity('alice', basedir=self.pbp_path, create=True)
        publickey.Identity('bob', basedir=self.pbp_path, create=True)
        publickey.Identity('carol', basedir=self.pbp_path, create=True)
        msg=self.tmp_dir+'/msg'
        msg2=self.tmp_dir+'/msg2'
        ct=self.tmp_dir+'/ct'
        with open(msg, 'w') as fd:
            fd.write('0' * 1080)

        pbp.encrypt_handler(infile=msg, outfile=ct, recipient=['bob','carol'], self='alice', basedir=self.pbp_path)
        pbp.decrypt_handler(infile=ct, outfile=msg2, self='bob', peer='alice', max_recipients = 20, basedir=self.pbp_path)

        with open(msg2, 'r') as fd:
            res = fd.read()
        self.assertEquals(res, '0'*1080)

        pbp.decrypt_handler(infile=ct, outfile=msg2, self='carol', peer='alice', max_recipients = 20, basedir=self.pbp_path)

        with open(msg2, 'r') as fd:
            res = fd.read()
        self.assertEquals(res, '0'*1080)

    def test_sign_handler(self):
        publickey.Identity('alice', basedir=self.pbp_path, create=True)
        publickey.Identity('bob', basedir=self.pbp_path, create=True)
        msg=self.tmp_dir+'/msg'
        msg2=self.tmp_dir+'/msg2'
        signed=self.tmp_dir+'/signed'
        with open(msg, 'w') as fd:
            fd.write('0' * 1080)

        pbp.sign_handler(infile=msg, outfile=signed, self='alice', basedir=self.pbp_path)
        sender = pbp.verify_handler(infile=signed, outfile=msg2, basedir=self.pbp_path)

        with open(msg2, 'r') as fd:
            res = fd.read()
        self.assertEquals(res, '0'*1080)
        self.assertEquals(sender, 'alice')

    def test_keysign(self):
        publickey.Identity('alice', basedir=self.pbp_path, create=True)
        publickey.Identity('bob', basedir=self.pbp_path, create=True)
        pbp.keysign_handler(name='bob', self='alice', basedir=self.pbp_path)
        sigs=pbp.keycheck_handler(name='bob', basedir=self.pbp_path)
        self.assertEquals(sigs, ['alice'])

    def test_export(self): # also tests import
        publickey.Identity('alice', basedir=self.pbp_path, create=True)
        publickey.Identity('bob', basedir=self.tmp_dir, create=True)
        export = pbp.export_handler('alice', basedir=self.pbp_path)
        key=self.tmp_dir+'/key.exp'
        with open(key, 'w') as fd:
            fd.write(export)
        pbp.import_handler(infile=key, basedir=self.tmp_dir)
        pks=publickey.get_public_keys(basedir=self.tmp_dir)
        self.assertEquals([p.name for p in pks if p.name!='bob'], ['alice'])

    def test_hash(self):
        msg=self.tmp_dir+'/msg'
        with open(msg, 'w') as fd:
            fd.write('0' * 1080)
        h=pbp.hash_handler(infile=msg, k='', outlen=16)
        self.assertEquals(h, '%\x80\x1e\xc8\x0c\x17\x89Z_I\x15\x19.Z P')
        h=pbp.hash_handler(infile=msg, k='some random "key" with 32 byte output', outlen=32)
        print repr(h)
        self.assertEquals(h,"\xae\xf5\x84\x9cr\xf5D1D\x9e}&\x18\xa5Q&LMw\xe3\xa08y\xbf~'\xf5\x0b\x9a\xe4\xd9\x97")


    def tearDown(self):
        rmtree(self.tmp_dir)

    def gen_key(self):
        self.numkeys += 1
        return publickey.Identity(NAME + str(self.numkeys), basedir=self.pbp_path, create=True)

if __name__ == '__main__':
    unittest.main()
