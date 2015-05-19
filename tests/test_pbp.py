#!/usr/bin/env python2
# -*- coding: utf-8 -*-

from tempfile import mkdtemp
from shutil import rmtree
import unittest, pbp, os, re
from pbp import pbp, publickey, chaining, ecdh

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

    def test_3mpecdh(self):
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

    def test_4mpecdh(self):
        p1 = ecdh.MPECDH(1, peers=4)
        p2 = ecdh.MPECDH(2, peers=4)
        p3 = ecdh.MPECDH(3, peers=4)
        p4 = ecdh.MPECDH(4, peers=4)
        # four way
        p3.mpecdh2(p2.mpecdh2(p1.mpecdh2(p4.mpecdh1(p3.mpecdh1(p2.mpecdh1(p1.mpecdh1()))))))
        self.assertEquals(p1.secret,p2.secret)
        self.assertEquals(p2.secret,p3.secret)
        self.assertEquals(p3.secret,p4.secret)

    def test_chaining(self):
        publickey.Identity('alice', basedir=self.pbp_path, create=True)
        publickey.Identity('bob', basedir=self.pbp_path, create=True)

        msg=self.tmp_dir+'/msg'
        msg2=self.tmp_dir+'/msg2'
        ct=self.tmp_dir+'/ct'

        sender, receiver = 'alice', 'bob'

        for i in xrange(10):
            with open(msg, 'w') as fd:
                fd.write(str(i) * 1080)

            pbp.chaining_encrypt_handler(infile=msg, outfile=ct, recipient=receiver, self=sender, basedir=self.pbp_path)
            pbp.chaining_decrypt_handler(infile=ct, outfile=msg2, recipient=sender, self=receiver, basedir=self.pbp_path)

            with open(msg2, 'r') as fd:
                res = fd.read()
            self.assertEquals(res, str(i)*1080)

            sender,receiver=receiver,sender

    def test_oob_chaining(self):
        # this test is sadly ugly, sorry.

        publickey.Identity('alice', basedir=self.pbp_path, create=True)
        publickey.Identity('bob', basedir=self.pbp_path, create=True)

        msg=self.tmp_dir+'/msg'
        msg2=self.tmp_dir+'/msg2'
        ct=self.tmp_dir+'/ct'
        ct2=self.tmp_dir+'/ct2'
        ct3=self.tmp_dir+'/ct3'
        ct4=self.tmp_dir+'/ct4'
        ct5=self.tmp_dir+'/ct5'

        sender, receiver = 'alice', 'bob'

        # do some proper exchange
        for i in xrange(5):
            with open(msg, 'w') as fd:
                fd.write(str(i) * 1080)

            pbp.chaining_encrypt_handler(infile=msg, outfile=ct, recipient=receiver, self=sender, basedir=self.pbp_path)
            pbp.chaining_decrypt_handler(infile=ct, outfile=msg2, recipient=sender, self=receiver, basedir=self.pbp_path)

            with open(msg2, 'r') as fd:
                res = fd.read()
            self.assertEquals(res, str(i)*1080)

            sender,receiver=receiver,sender

        with open(msg, 'w') as fd:
            fd.write('a' * 1080)

        pbp.chaining_encrypt_handler(infile=msg, outfile=ct, recipient='alice', self='bob', basedir=self.pbp_path)
        pbp.chaining_decrypt_handler(infile=ct, outfile=msg2, recipient='bob', self='alice', basedir=self.pbp_path)

        with open(msg2, 'r') as fd:
            res = fd.read()
        self.assertEquals(res, 'a'*1080)

        # resend previous message
        pbp.chaining_encrypt_handler(infile=msg, outfile=ct, recipient='alice', self='bob', basedir=self.pbp_path)
        pbp.chaining_decrypt_handler(infile=ct, outfile=msg2, recipient='bob', self='alice', basedir=self.pbp_path)

        with open(msg2, 'r') as fd:
            res = fd.read()
        self.assertEquals(res, 'a'*1080)

        # answer message but mess up order
        # would be nice to have random tests here, instead of the following synthetic
        # b3,a1,b2,b1,a2 - where the letter is the recipent, and the number the order of creation
        # 1st msg
        with open(msg, 'w') as fd: fd.write('b1' * 1080)
        pbp.chaining_encrypt_handler(infile=msg, outfile=ct, recipient='bob', self='alice', basedir=self.pbp_path)
        # 2nd msg
        with open(msg, 'w') as fd: fd.write('b2' * 1080)
        pbp.chaining_encrypt_handler(infile=msg, outfile=ct2, recipient='bob', self='alice', basedir=self.pbp_path)
        # 3rd msg
        with open(msg, 'w') as fd: fd.write('b3' * 1080)
        pbp.chaining_encrypt_handler(infile=msg, outfile=ct3, recipient='bob', self='alice', basedir=self.pbp_path)
        # and 1st message in the other direction at the same time
        with open(msg, 'w') as fd: fd.write('a1' * 1080)
        pbp.chaining_encrypt_handler(infile=msg, outfile=ct4, recipient='alice', self='bob', basedir=self.pbp_path)
        # 2nd message in the other direction at the same time
        with open(msg, 'w') as fd: fd.write('a2' * 1080)
        pbp.chaining_encrypt_handler(infile=msg, outfile=ct5, recipient='alice', self='bob', basedir=self.pbp_path)

        # 3rd msg decrypt
        pbp.chaining_decrypt_handler(infile=ct3, outfile=msg2, recipient='alice', self='bob', basedir=self.pbp_path)
        with open(msg2, 'r') as fd: res = fd.read()
        self.assertEquals(res, 'b3'*1080)

        # other direction decrypt
        pbp.chaining_decrypt_handler(infile=ct4, outfile=msg2, recipient='bob', self='alice', basedir=self.pbp_path)
        with open(msg2, 'r') as fd: res = fd.read()
        self.assertEquals(res, 'a1'*1080)

        # 2nd msg decrypt
        pbp.chaining_decrypt_handler(infile=ct2, outfile=msg2, recipient='alice', self='bob', basedir=self.pbp_path)
        with open(msg2, 'r') as fd: res = fd.read()
        self.assertEquals(res, 'b2'*1080)
        # 1st msg decrypt
        pbp.chaining_decrypt_handler(infile=ct, outfile=msg2, recipient='alice', self='bob', basedir=self.pbp_path)
        with open(msg2, 'r') as fd: res = fd.read()
        self.assertEquals(res, 'b1'*1080)
        # other direction 2nd decrypt
        pbp.chaining_decrypt_handler(infile=ct5, outfile=msg2, recipient='bob', self='alice', basedir=self.pbp_path)
        with open(msg2, 'r') as fd: res = fd.read()
        self.assertEquals(res, 'a2'*1080)

    def test_lower_chaining(self):
        publickey.Identity('alice', basedir=self.pbp_path, create=True)
        publickey.Identity('bob', basedir=self.pbp_path, create=True)

        alice = chaining.ChainingContext('alice','bob', self.pbp_path)
        bob = chaining.ChainingContext('bob','alice',self.pbp_path)

        alice.load()
        bob.load()

        c,n = alice.send('howdy')
        self.assertEquals('howdy', bob.receive(c,n))

        c,n = bob.send('howdy')
        self.assertEquals('howdy', alice.receive(c,n))

        c,n = alice.send('howdy')
        self.assertEquals('howdy', bob.receive(c,n))

        c,n = alice.send('howdy')
        self.assertEquals('howdy', bob.receive(c,n))

        c,n = bob.send('howdy')
        self.assertEquals('howdy', alice.receive(c,n))

        c,n = alice.send('howdy')
        self.assertEquals('howdy', bob.receive(c,n))

        c,n = bob.send('howdy')
        self.assertEquals('howdy', alice.receive(c,n))

        c,n = alice.send('howdy')
        self.assertEquals('howdy', bob.receive(c,n))

        c,n = bob.send('howdy')
        self.assertEquals('howdy', alice.receive(c,n))

        c,n = alice.send('howdy')
        # lose packet
        c,n = alice.send('howdy')
        self.assertEquals('howdy', bob.receive(c,n))

        # cross send and loose packets
        c,n = bob.send('howdy')
        c,n = bob.send('howdy')
        # crossing packets
        c1,n1 = alice.send('howdy')
        self.assertEquals('howdy', alice.receive(c,n))
        self.assertEquals('howdy', bob.receive(c1,n1))

        # continue normal sending
        c,n = alice.send('howdy')
        self.assertEquals('howdy', bob.receive(c,n))

        # out of bound sending
        c,n = bob.send('howdy')
        c1,n1 = bob.send('howdy')
        # crossing packets
        c2,n2 = alice.send('howdy')
        self.assertEquals('howdy', alice.receive(c1,n1))
        self.assertEquals('howdy', alice.receive(c,n))
        self.assertEquals('howdy', bob.receive(c2,n2))

        # continue normal sending
        c,n = alice.send('ok')
        self.assertEquals('ok', bob.receive(c,n))

        bob.save()
        alice.save()

        alice1 = chaining.ChainingContext('alice','bob', self.pbp_path)
        bob1 = chaining.ChainingContext('bob','alice', self.pbp_path)

        alice1.load()
        bob1.load()

        c,n = alice1.send('howdy')
        self.assertEquals('howdy', bob1.receive(c,n))

        c,n = bob1.send('howdy')
        self.assertEquals('howdy', alice1.receive(c,n))

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
