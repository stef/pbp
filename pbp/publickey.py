#!/usr/bin/env python2
import pysodium as nacl, scrypt # external dependencies
import os, stat,  getpass, datetime, binascii
from itertools import imap
from utils import split_by_n, b85encode
from SecureString import clearmem
import pbp

class Identity(object):
    def __init__(self, name, basedir=None, create=False, publicOnly=False):
        """initializes the Identity from the keystore or creates one"""
        self.name=name
        self.publicOnly=publicOnly
        self.basedir=os.path.expandvars(
            os.path.expanduser(basedir or pbp.defaultbase))

        if create:
            if not os.path.exists(self.basedir):
                for d in (get_pk_dir(self.basedir), get_sk_dir(self.basedir)):
                    os.makedirs(d, stat.S_IREAD|stat.S_IWRITE|stat.S_IEXEC)
            self.create()

    def __getattr__(self,name):
        if name in ['ms', 'mp', 'cs', 'cp',
                    'ss', 'sp', 'created', 'valid']:
            if name[1:]=='s' and self.publicOnly: return None
            self.loadkey(name)
            return getattr(self, name)

    def keyid(self):
        res = nacl.crypto_generichash(''.join((self.created.isoformat(),
                                                self.valid.isoformat(),
                                                self.mp,
                                                self.sp,
                                                self.cp
                                                )))[:16]
        return ' '.join(split_by_n(binascii.b2a_hex(res).decode("ascii"), 4))

    def create(self):
        self.created = datetime.datetime.utcnow()
        self.valid = datetime.datetime.utcnow() + datetime.timedelta(days=365)
        self.mp, self.ms = nacl.crypto_sign_keypair()
        self.sp, self.ss = nacl.crypto_sign_keypair()
        self.cp, self.cs = nacl.crypto_box_keypair()
        self.save()

    def save(self):
        # save secret master key
        if self.ms:
            self.savesecretekey("mk", self.ms)
        # save secret sub-keys
        if self.cs or self.ss:
            self.savesecretekey("sk", self.ss+self.cs)
        # save public keys
        self.savepublickeys()

    def __repr__(self):
        return "name: %s\nkeyid: %s\nvalid: %s - %s\nmp: %s\nms: %s\n" \
               "cp: %s\ncs: %s\nsp: %s\nss: %s\n" % (self.name,
                                                     self.keyid(),
                                                     self.created.isoformat(),
                                                     self.valid.isoformat(),
                                                     b85encode(self.mp),
                                                     self.ms is not None,
                                                     b85encode(self.cp),
                                                     self.cs is not None,
                                                     b85encode(self.sp),
                                                     self.ss is not None)


    def loadkey(self, type):
        if type in ['mp','cp','sp', 'created', 'valid']:
            with open(get_pk_filename(self.basedir, self.name), 'r') as fd:
                tmp=fd.read()
            mk=tmp[nacl.crypto_sign_BYTES:nacl.crypto_sign_BYTES+nacl.crypto_sign_PUBLICKEYBYTES]
            tmp = nacl.crypto_sign_open(tmp, mk)
            if type == 'mp': self.mp=mk
            i=nacl.crypto_sign_PUBLICKEYBYTES
            if type == 'sp': self.sp=tmp[i:i+nacl.crypto_sign_PUBLICKEYBYTES]
            i+=nacl.crypto_sign_PUBLICKEYBYTES
            if type == 'cp': self.cp=tmp[i:i+nacl.crypto_box_PUBLICKEYBYTES]
            i+=nacl.crypto_box_PUBLICKEYBYTES
            self.created = parse_isodatetime(tmp[i:i + 32])
            self.valid = parse_isodatetime(tmp[i + 32:i + 64])

        elif type in ['cs', 'ss']:
            tmp = get_sk_filename(self.basedir, self.name)
            if os.path.exists(tmp):
                tmp = self.decrypt_with_user_pw(tmp, 'subkeys')
                if type == 'ss': self.ss = tmp[:nacl.crypto_sign_SECRETKEYBYTES]
                if type == 'cs': self.cs = tmp[nacl.crypto_sign_SECRETKEYBYTES:]

        elif type == 'ms':
            tmp = get_sk_filename(self.basedir, self.name, ext='mk')
            if os.path.exists(tmp):
                self.ms = self.decrypt_with_user_pw(tmp, 'master key')

    def decrypt_with_user_pw(self, filename, pw_for):
        with file(filename) as fd:
            nonce = fd.read(nacl.crypto_secretbox_NONCEBYTES)
            prompt = 'Passphrase for decrypting {0} for {1}: '.format(pw_for, self.name)
            k = scrypt.hash(getpass.getpass(prompt), pbp.scrypt_salt)[:nacl.crypto_secretbox_KEYBYTES]
            return nacl.crypto_secretbox_open(fd.read(), nonce, k)

    def savepublickeys(self):
        with open(get_pk_filename(self.basedir, self.name), 'w') as fd:
            dates='{:<32}{:<32}'.format(self.created.isoformat(), self.valid.isoformat())
            fd.write(nacl.crypto_sign(self.mp+self.sp+self.cp+dates+self.name, self.ms))

    def savesecretekey(self, ext, key):
        fname = get_sk_filename(self.basedir, self.name, ext)
        k = pbp.getkey(nacl.crypto_secretbox_KEYBYTES,
                       empty=True,
                       text='Master' if ext == 'mk' else 'Subkey')
        nonce = nacl.randombytes(nacl.crypto_secretbox_NONCEBYTES)
        with open(fname,'w') as fd:
            fd.write(nonce)
            fd.write(nacl.crypto_secretbox(key, nonce, k))

    def keyencrypt(self, key, recipients=None):
        c=[]
        for r in recipients:
            nonce = nacl.randombytes(nacl.crypto_box_NONCEBYTES)
            c.append((nonce, nacl.crypto_box(key, nonce, r.cp, self.cs)))
        return c

    def encrypt(self, msg, recipients=None):
        mk = nacl.randombytes(nacl.crypto_secretbox_KEYBYTES)
        c = self.keyencrypt(mk, recipients)
        nonce = nacl.randombytes(nacl.crypto_secretbox_NONCEBYTES)
        return (nonce, c, nacl.crypto_secretbox(msg, nonce, mk))

    def keydecrypt(self, peers):
        for nonce, ck in peers:
            for keys in get_public_keys(basedir=self.basedir):
                try:
                    key = nacl.crypto_box_open(ck, nonce, keys.cp, self.cs)
                except ValueError:
                    continue
                return (keys.name, key)
        return None, None

    def decrypt(self, pkt):
        peer, key = self.keydecrypt(pkt[1])
        if key:
            return peer, nacl.crypto_secretbox_open(pkt[2], pkt[0], key)

    def sign(self, msg, master=False):
        signing_key = self.ms if master else self.ss
        return nacl.crypto_sign(msg, signing_key)

    def clear(self):
        if 'ms' in self.__dict__.keys():
            clearmem(self.ms)
            del self.ms
        if 'ms' in self.__dict__.keys():
            clearmem(self.cs)
            del self.cs
        if 'ms' in self.__dict__.keys():
            clearmem(self.ss)
            del self.ss

def verify(msg, master=False, basedir=None):
    for keys in get_public_keys(basedir=basedir or pbp.defaultbase):
        try:
            verifying_key = keys.mp if master else keys.sp
            return keys.name, nacl.crypto_sign_open(msg, verifying_key)
        except ValueError: pass

def get_public_keys(basedir=None):
    if not basedir: basedir=pbp.defaultbase
    basedir=os.path.expandvars(os.path.expanduser(basedir))
    pk_dir = get_pk_dir(basedir)
    if not os.path.exists(pk_dir):
        return
    for root, ext in imap(os.path.splitext, os.listdir(pk_dir)):
        if ext == '.pk':
            yield Identity(root, publicOnly=True, basedir=basedir)

def get_secret_keys(basedir=None):
    if not basedir: basedir=pbp.defaultbase
    basedir=os.path.expandvars(os.path.expanduser(basedir))
    seen = set()
    sk_dir = get_sk_dir(basedir)
    if not os.path.exists(sk_dir):
        return
    for root, ext in imap(os.path.splitext, os.listdir(sk_dir)):
        if ext in ('.mk', '.sk') and root not in seen:
            seen.add(root)
            yield Identity(root, basedir=basedir)

def parse_isodatetime(value):
    return datetime.datetime.strptime(value.strip(), "%Y-%m-%dT%H:%M:%S.%f")

def get_sk_filename(basedir, name, ext='sk'):
    return os.path.join(get_sk_dir(basedir), name + '.' + ext)

def get_pk_filename(basedir, name):
    return os.path.join(get_pk_dir(basedir), name + '.pk')

def get_sk_dir(basedir):
    return os.path.join(basedir, 'sk')

def get_pk_dir(basedir):
    return os.path.join(basedir, 'pk')

def test():
    me = Identity('me', create=True, basedir='test-pbp')
    you = Identity('you', create=True, basedir='test-pbp')
    print me
    print you
    print you.decrypt(me.encrypt('howdy', [you]))
    print verify(me.sign('howdy'), basedir='test-pbp')

if __name__ == '__main__':
    test()
