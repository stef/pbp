#!/usr/bin/env python
import nacl, scrypt, iso8601 # external dependencies
import argparse, os, stat,  getpass, datetime, sys, struct, binascii
from utils import split_by_n, b85encode

# TODO make processing buffered!
# TODO add output armoring

defaultbase='~/.pbp'
scrypt_salt = 'qa~t](84z<1t<1oz:ik.@IRNyhG=8q(on9}4#!/_h#a7wqK{Nt$T?W>,mt8NqYq&6U<GB1$,<$j>,rSYI2GRDd:Bcm'

_prev_passphrase = ''

class Identity(object):
    def __init__(self, name, basedir=defaultbase, create=False, publicOnly=False):
        """initializes the Identity from the keystore or creates one"""
        self.name=name
        self.publicOnly=publicOnly
        self.basedir=os.path.expandvars(
            os.path.expanduser(basedir))

        if create:
            if not os.path.exists(self.basedir):
                os.mkdir(self.basedir)
                os.chmod(self.basedir,
                         stat.S_IREAD|stat.S_IWRITE|stat.S_IEXEC)
                os.mkdir(self.basedir+'/pk')
                os.mkdir(self.basedir+'/sk')
            self.create()

    def __getattr__(self,name):
        if name in ['ms', 'mp', 'cs', 'cp',
                    'ss', 'sp', 'created', 'valid']:
            if name[1:]=='s' and self.publicOnly: return None
            self.loadkey(name)
            return getattr(self, name)

    def keyid(self):
        res = nacl.crypto_hash_sha256(''.join((self.created.isoformat(),
                                                self.valid.isoformat(),
                                                self.mp,
                                                self.sp,
                                                self.cp
                                                )))[:16]
        return ' '.join(split_by_n(binascii.b2a_hex(res).decode("ascii"), 4))

    def create(self):
        self.created = datetime.datetime.now()
        self.valid = datetime.datetime.now() + datetime.timedelta(days=365)
        self.mp, self.ms = nacl.crypto_sign_keypair()
        self.sp, self.ss = nacl.crypto_sign_keypair()
        self.cp, self.cs = nacl.crypto_box_keypair()
        self.save()

    def save(self):
        # save secret master key
        if self.ms:
            print >>sys.stderr, "Master ",
            self.savesecretekey("mk", self.ms)
        # save secret sub-keys
        if self.cs or self.ss:
            print >>sys.stderr, "Subkey ",
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
            with open("%s/pk/%s.pk" % (self.basedir, self.name), 'r') as fd:
                tmp=fd.read()
            mk=tmp[nacl.crypto_sign_PUBLICKEYBYTES:nacl.crypto_sign_PUBLICKEYBYTES*2]
            tmp = nacl.crypto_sign_open(tmp, mk)
            if type == 'mp': self.mp=mk
            i=nacl.crypto_sign_PUBLICKEYBYTES
            if type == 'sp': self.sp=tmp[i:i+nacl.crypto_sign_PUBLICKEYBYTES]
            i+=nacl.crypto_sign_PUBLICKEYBYTES
            if type == 'cp': self.cp=tmp[i:i+nacl.crypto_box_PUBLICKEYBYTES]
            i+=nacl.crypto_box_PUBLICKEYBYTES
            self.created=iso8601.parse_date(tmp[i:i+32].strip())
            self.valid=iso8601.parse_date(tmp[i+32:i+64].strip())

        elif type in ['cs', 'ss']:
            tmp="%s/sk/%s.sk" % (self.basedir, self.name)
            if os.path.exists(tmp):
                with open(tmp, 'r') as fd:
                    nonce = fd.read(nacl.crypto_secretbox_NONCEBYTES)
                    k = scrypt.hash(getpass.getpass('Passphrase for decrypting subkeys for %s: ' % self.name),
                                    scrypt_salt)[:nacl.crypto_secretbox_KEYBYTES]
                    tmp=nacl.crypto_secretbox_open(fd.read(), nonce, k)
                    i=nacl.crypto_sign_SECRETKEYBYTES
                    if type == 'ss': self.ss=tmp[:i]
                    if type == 'cs': self.cs=tmp[i:]

        elif type == 'ms':
            tmp="%s/sk/%s.mk" % (self.basedir, self.name)
            if os.path.exists(tmp):
                with open(tmp, 'r') as fd:
                    nonce = fd.read(nacl.crypto_secretbox_NONCEBYTES)
                    k = scrypt.hash(getpass.getpass('Passphrase for decrypting master key for %s: ' % self.name),
                                    scrypt_salt)[:nacl.crypto_secretbox_KEYBYTES]
                    tmp=nacl.crypto_secretbox_open(fd.read(), nonce, k)
                    self.ms=tmp

    def savepublickeys(self):
        with open("%s/pk/%s.pk" % (self.basedir, self.name),'w') as fd:
            dates='{:<32}{:<32}'.format(self.created.isoformat(), self.valid.isoformat())
            fd.write(nacl.crypto_sign(self.mp+self.sp+self.cp+dates+self.name, self.ms))

    def savesecretekey(self, ext, key):
        fname="%s/sk/%s.%s" % (self.basedir, self.name, ext)
        k = getkey(nacl.crypto_secretbox_KEYBYTES, empty=True)
        nonce = nacl.randombytes(nacl.crypto_secretbox_NONCEBYTES)
        with open(fname,'w') as fd:
            fd.write(nonce)
            fd.write(nacl.crypto_secretbox(key, nonce, k))

    @staticmethod
    def getpkeys(basedir=defaultbase):
        basedir=os.path.expandvars(os.path.expanduser(basedir))
        for k in os.listdir("%s/pk/" % basedir):
            if k.endswith('.pk'):
                yield Identity(k[:-3], publicOnly=True, basedir=basedir)

    @staticmethod
    def getskeys(basedir=defaultbase):
        basedir=os.path.expandvars(os.path.expanduser(basedir))
        seen=[]
        for k in os.listdir("%s/sk/" % basedir):
            if k[-3:] in ['.mk','.sk'] and k[:-3] not in seen:
                seen.append(k[:-3])
                yield Identity(k[:-3], basedir=basedir)

def getkey(l, pwd='', empty=False):
    # queries the user for a passphrase if neccessary, and
    # returns a scrypted key of length l
    global _prev_passphrase
    if not pwd:
        pwd2 = not pwd
        if len(_prev_passphrase)>0:
            print >>sys.stderr, "press enter to reuse the previous passphrase"
        while pwd != pwd2 or (not empty and not pwd.strip()):
            pwd = getpass.getpass('1/2 Passphrase: ')
            if len(pwd.strip()):
                pwd2 = getpass.getpass('2/2 Repeat passphrase: ')
            elif _prev_passphrase != None:
                pwd = _prev_passphrase
                break
    if pwd.strip():
        _prev_passphrase = pwd
        return scrypt.hash(pwd, scrypt_salt)[:l]

def encrypt(msg, recipients=None, stream=False, pwd=None, self=None):
    # encrypts msg
    if not recipients:
        if stream:
            nonce = nacl.randombytes(nacl.crypto_stream_NONCEBYTES)
            k = getkey(nacl.crypto_stream_KEYBYTES, pwd=pwd)
            return ('s', nonce, nacl.crypto_stream_xor(msg, nonce, k))
        nonce = nacl.randombytes(nacl.crypto_secretbox_NONCEBYTES)
        k = getkey(nacl.crypto_secretbox_KEYBYTES, pwd=pwd)
        return ('c', nonce, nacl.crypto_secretbox(msg, nonce, k))
    sk = self.cs
    mk = nacl.randombytes(nacl.crypto_stream_KEYBYTES)
    c=[]
    for r in recipients:
        nonce = nacl.randombytes(nacl.crypto_box_NONCEBYTES)
        c.append((nonce, nacl.crypto_box(mk, nonce, r.cp, sk)))
    nonce = nacl.randombytes(nacl.crypto_secretbox_NONCEBYTES)
    return ('a', nonce, c, nacl.crypto_secretbox(msg, nonce, mk))

def decrypt(pkt, self=None, pwd=None, basedir=None):
    if pkt[0]=='s':
        # stream
        if not pwd: pwd = getpass.getpass('Passphrase for decrypting: ')
        k = scrypt.hash(pwd, scrypt_salt)[:nacl.crypto_secretbox_KEYBYTES]

        return nacl.crypto_stream_xor(pkt[2], pkt[1], k)
    if pkt[0]=='c':
        # symmetric
        if not pwd: pwd = getpass.getpass('Passphrase for decrypting: ')
        k = scrypt.hash(pwd, scrypt_salt)[:nacl.crypto_secretbox_KEYBYTES]

        return nacl.crypto_secretbox_open(pkt[2], pkt[1], k)

    sk = self.cs
    source = None
    mk = None
    for nonce, ck in pkt[2]:
        for keys in Identity.getpkeys(basedir=basedir):
            try:
                mk = nacl.crypto_box_open(ck, nonce, keys.cp, sk)
            except ValueError:
                continue
            source = keys.name
            break
        if source:
            break
    return source, nacl.crypto_secretbox_open(pkt[3], pkt[1], mk)

def sign(msg, self, master=False):
    if master:
        return nacl.crypto_sign(msg, self.ms)
    return nacl.crypto_sign(msg, self.ss)

def verify(msg, basedir=defaultbase, master=False):
    for keys in Identity.getpkeys(basedir=basedir):
        if not master:
            try:
                return keys.name, nacl.crypto_sign_open(msg, keys.sp)
            except ValueError: pass
        else:
            try:
                return keys.name, nacl.crypto_sign_open(msg, keys.mp)
            except ValueError: pass

def encrypt_handler(opts):
    with open(opts.infile,'r') as fd:
        msg=fd.read()
    output_filename = opts.outfile if opts.outfile else opts.infile + '.pbp'
    if opts.recipient:
        # let's do public key encryption
        if not opts.self:
            print >>sys.stderr, "Error: need to specify your own key using the --self param"
            sys.exit(1)
        type, nonce, r, cipher = encrypt(msg,
                                         recipients=[Identity(x, basedir=opts.basedir)
                                                     for x
                                                     in opts.recipient],
                                         self=Identity(opts.self, basedir=opts.basedir))
        if type!='a':
            print >>sys.stderr, "Error: wrong encryption type"
            sys.exit(1)
        with open(output_filename, 'w') as fd:
            fd.write(struct.pack("B",5))
            fd.write(nonce)
            fd.write(struct.pack("L",len(r)))
            for rnonce, ct in r:
                fd.write(rnonce)
                fd.write(struct.pack("B",len(ct)))
                fd.write(ct)
            fd.write(cipher)
    else:
        # let's do symmetric crypto
        type, nonce, cipher = encrypt(msg)
        # until we pass a param to encrypt above, it will always be block cipher
        if type=='c':
            with open(output_filename, 'w') as fd:
                fd.write(struct.pack("B",23))
                fd.write(nonce)
                fd.write(cipher)
        elif type=='s':
            # use the stream cipher
            with open(output_filename ,'w') as fd:
                fd.write(struct.pack("B",42))
                fd.write(nonce)
                fd.write(cipher)
        else:
            print >>sys.stderr, "Error: no symmetric key structure found"
            sys.exit(1)

def decrypt_handler(opts):
    with open(opts.infile,'r') as fd:
        type=struct.unpack('B',fd.read(1))[0]
        # asym
        if type == 5:
            if not opts.self:
                print >>sys.stderr, "Error: need to specify your own key using the --self param"
                sys.exit(1)
            nonce = fd.read(nacl.crypto_secretbox_NONCEBYTES)
            size = struct.unpack('L',fd.read(4))[0]
            r=[]
            while size>0:
                size-=1
                rnonce=fd.read(nacl.crypto_box_NONCEBYTES)
                ct = fd.read(struct.unpack('B',fd.read(1))[0])
                r.append((rnonce,ct))
            sender, msg = decrypt(('a',
                                   nonce,
                                   r,
                                   fd.read()),
                                  basedir=opts.basedir,
                                  self=Identity(opts.self, basedir=opts.basedir)) or ('', 'decryption failed')
            if sender:
                print >>sys.stderr, 'good message from', sender
                print msg
            else:
                print >>sys.stderr, msg
            return

        # sym
        elif type == 23:
            nonce = fd.read(nacl.crypto_secretbox_NONCEBYTES)
            msg = decrypt(('c', nonce, fd.read()))

        # stream
        elif type == 42:
            nonce = fd.read(nacl.crypto_stream_NONCEBYTES)
            msg = decrypt(('s', nonce, fd.read()))

        if len(msg):
            print msg
        else:
            print >>sys.stderr,  'decryption failed'

def signhandler(opts):
    with open(opts.infile,'r') as fd:
        data = fd.read()
    with open(opts.infile+'.sig','w') as fd:
        fd.write(sign(data, self=Identity(opts.self, basedir=opts.basedir)))

def keysignhandler(opts):
    fname="%s/pk/%s.pk" % (opts.basedir, opts.name)
    with open(fname,'r') as fd:
        data = fd.read()
    with open(fname+'.sig','a') as fd:
        sig = sign(data,
                   self=Identity(opts.self, basedir=opts.basedir),
                   master=True)
        fd.write(sig[:32]+sig[-32:])

def keycheckhandler(opts):
    fname="%s/pk/%s.pk" % (opts.basedir, opts.name)
    with open(fname,'r') as fd:
        pk = fd.read()
    sigs=[]
    with open(fname+".sig",'r') as fd:
        sigdat=fd.read()
    i=0
    while i<len(sigdat)/64:
        res = verify(sigdat[i*64:i*64+32]+pk+sigdat[i*64+32:i*64+64],
                     basedir=opts.basedir,
                     master=True)
        if res:
            sigs.append(res[0])
        i+=1
    print 'good signatures on', opts.name, 'from', ', '.join(sigs)

def verifyhandler(opts):
    with open(opts.infile,'r') as fd:
        data = fd.read()
    sender, msg = verify(data, basedir=opts.basedir) or ('', 'verification failed')
    if len(sender)>0:
        print msg
        print >>sys.stderr, "good message from", sender
    else:
        print >>sys.stderr, msg

def main():
    parser = argparse.ArgumentParser(description='Pretty Better Privacy')
    group = parser.add_mutually_exclusive_group()
    group.add_argument('--gen-key',     '-g',  dest='action', action='store_const', const='g', help="generates a new key")
    group.add_argument('--encrypt',     '-c',  dest='action', action='store_const', const='c',help="encrypts stdin")
    group.add_argument('--decrypt',     '-d',  dest='action', action='store_const', const='d',help="decrypts stdin")
    group.add_argument('--sign',        '-s',  dest='action', action='store_const', const='s',help="signs stdin")
    group.add_argument('--master-sign', '-m',  dest='action', action='store_const', const='m',help="signs stdin with your masterkey")
    group.add_argument('--verify',      '-v',  dest='action', action='store_const', const='v',help="verifies stdin")
    group.add_argument('--list',        '-l',  dest='action', action='store_const', const='l',help="lists public keys")
    group.add_argument('--list-secret', '-L',  dest='action', action='store_const', const='L',help="Lists secret keys")
    group.add_argument('--check-sigs',  '-C',  dest='action', action='store_const', const='C',help="lists all known sigs on a public key")

    parser.add_argument('--recipient',  '-r', action='append', help="designates a recipient for public key encryption")
    parser.add_argument('--name',       '-n', help="sets the name for a new key")
    parser.add_argument('--basedir',    '-b', '--base-dir', help="designates a recipient for public key encryption", default=defaultbase)
    parser.add_argument('--self',       '-S', help="sets your own key")
    parser.add_argument('--infile',     '-i', help="file to operate on")
    parser.add_argument('--armor',      '-a', action='store_true', help="ascii armors the output [TODO]")
    parser.add_argument('--outfile',    '-o', help="file to operate on")
    opts=parser.parse_args()

    opts.basedir=os.path.expandvars( os.path.expanduser(opts.basedir))
    # Generate key
    if opts.action=='g':
        if not opts.name:
            print >>sys.stderr, "Error: need to specify a Name for the key using the -n param"
            sys.exit(1)
        Identity(opts.name, create=True, basedir=opts.basedir)

    # list public keys
    elif opts.action=='l':
        for i in Identity.getpkeys(opts.basedir):
            print ('valid' if i.valid > iso8601.parse_date(datetime.datetime.now().isoformat()) > i.created
                   else 'invalid'), i.keyid(), i.name

    # list secret keys
    elif opts.action=='L':
        for i in Identity.getskeys(opts.basedir):
            print ('valid' if i.valid > iso8601.parse_date(datetime.datetime.now().isoformat()) > i.created
                   else 'invalid'), i.keyid(), i.name

    # encrypt
    elif opts.action=='c':
        if not opts.infile:
            print >>sys.stderr, "Error: need to specify a file to " \
                                "operate on using the --in param"
            sys.exit(1)
        encrypt_handler(opts)

    # decrypt
    elif opts.action=='d':
        if not opts.infile:
            print >>sys.stderr, "Error: need to specify a file to operate " \
                                "on using the --in param"
            sys.exit(1)
        decrypt_handler(opts)

    # sign
    elif opts.action=='s':
        if not opts.infile:
            print >>sys.stderr, "Error: need to specify a file to operate " \
                                "on using the --in param"
            sys.exit(1)
        if not opts.self:
            print >>sys.stderr, "Error: need to specify your own key using " \
                                "the --self param"
            sys.exit(1)
        signhandler(opts)

    # key sign
    elif opts.action=='m':
        if not opts.name:
            print >>sys.stderr, "Error: need to specify a key to operate " \
                                "on using the --name param"
            sys.exit(1)
        if not opts.self:
            print >>sys.stderr, "Error: need to specify your own key using " \
                                "the --self param"
            sys.exit(1)
        keysignhandler(opts)

    # lists signatures owners on public keys
    elif opts.action=='C':
        if not opts.name:
            print >>sys.stderr, "Error: need to specify a key to operate " \
                                "on using the --name param"
            sys.exit(1)
        keycheckhandler(opts)

    # verify
    elif opts.action=='v':
        if not opts.infile:
            print >>sys.stderr, "Error: need to specify a file to operate " \
                                "on using the --in param"
            sys.exit(1)
        verifyhandler(opts)

if __name__ == '__main__':
    #__test()
    main()
