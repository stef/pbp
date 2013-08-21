#!/usr/bin/env python
import nacl, scrypt # external dependencies
import argparse, os, stat,  getpass, datetime, sys, struct, binascii
from utils import split_by_n, b85encode

# TODO make processing buffered!
# TODO add output armoring

ASYM_CIPHER = 5
BLOCK_CIPHER = 23
STREAM_CIPHER = 42

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
                os.mkdir(get_pk_dir(self.basedir))
                os.mkdir(get_sk_dir(self.basedir))
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
            mk=tmp[nacl.crypto_sign_PUBLICKEYBYTES:nacl.crypto_sign_PUBLICKEYBYTES*2]
            tmp = nacl.crypto_sign_open(tmp, mk)
            if type == 'mp': self.mp=mk
            i=nacl.crypto_sign_PUBLICKEYBYTES
            if type == 'sp': self.sp=tmp[i:i+nacl.crypto_sign_PUBLICKEYBYTES]
            i+=nacl.crypto_sign_PUBLICKEYBYTES
            if type == 'cp': self.cp=tmp[i:i+nacl.crypto_box_PUBLICKEYBYTES]
            i+=nacl.crypto_box_PUBLICKEYBYTES
            self.created=datetime.datetime.strptime(tmp[i:i+32].strip(),"%Y-%m-%dT%H:%M:%S.%f")
            self.valid=datetime.datetime.strptime(tmp[i+32:i+64].strip(),"%Y-%m-%dT%H:%M:%S.%f")

        elif type in ['cs', 'ss']:
            tmp = get_sk_filename(self.basedir, self.name)
            if os.path.exists(tmp):
                with open(tmp, 'r') as fd:
                    nonce = fd.read(nacl.crypto_secretbox_NONCEBYTES)
                    k = scrypt.hash(getpass.getpass('Passphrase for decrypting subkeys for %s: ' % self.name),
                                    scrypt_salt)[:nacl.crypto_secretbox_KEYBYTES]
                    tmp=nacl.crypto_secretbox_open(fd.read(), nonce, k)
                    if type == 'ss': self.ss=tmp[:nacl.crypto_sign_SECRETKEYBYTES]
                    if type == 'cs': self.cs=tmp[nacl.crypto_sign_SECRETKEYBYTES:]

        elif type == 'ms':
            tmp = get_sk_filename(self.basedir, self.name, ext='mk')
            if os.path.exists(tmp):
                with open(tmp, 'r') as fd:
                    nonce = fd.read(nacl.crypto_secretbox_NONCEBYTES)
                    k = scrypt.hash(getpass.getpass('Passphrase for decrypting master key for %s: ' % self.name),
                                    scrypt_salt)[:nacl.crypto_secretbox_KEYBYTES]
                    tmp=nacl.crypto_secretbox_open(fd.read(), nonce, k)
                    self.ms=tmp

    def savepublickeys(self):
        with open(get_pk_filename(self.basedir, self.name), 'w') as fd:
            dates='{:<32}{:<32}'.format(self.created.isoformat(), self.valid.isoformat())
            fd.write(nacl.crypto_sign(self.mp+self.sp+self.cp+dates+self.name, self.ms))

    def savesecretekey(self, ext, key):
        fname = get_sk_filename(self.basedir, self.name, ext)
        k = getkey(nacl.crypto_secretbox_KEYBYTES,
                   empty=True,
                   text='Master' if ext == 'mk' else 'Subkey')
        nonce = nacl.randombytes(nacl.crypto_secretbox_NONCEBYTES)
        with open(fname,'w') as fd:
            fd.write(nonce)
            fd.write(nacl.crypto_secretbox(key, nonce, k))

def getpkeys(basedir=defaultbase):
    basedir=os.path.expandvars(os.path.expanduser(basedir))
    pk_dir = get_pk_dir(basedir)
    if not os.path.exists(pk_dir):
        return
    for k in os.listdir(pk_dir):
        if k.endswith('.pk'):
            yield Identity(k[:-3], publicOnly=True, basedir=basedir)

def getskeys(basedir=defaultbase):
    basedir=os.path.expandvars(os.path.expanduser(basedir))
    seen = set()
    sk_dir = get_sk_dir(basedir)
    if not os.path.exists(sk_dir):
        return
    for k in os.listdir(sk_dir):
        if k[-3:] in ['.mk','.sk'] and k[:-3] not in seen:
            seen.add(k[:-3])
            yield Identity(k[:-3], basedir=basedir)

def get_sk_filename(basedir, name, ext='sk'):
    return os.path.join(get_sk_dir(basedir), name + '.' + ext)

def get_pk_filename(basedir, name):
    return os.path.join(get_pk_dir(basedir), name + '.pk')

def get_sk_dir(basedir):
    return os.path.join(basedir, 'sk')

def get_pk_dir(basedir):
    return os.path.join(basedir, 'pk')

def getkey(l, pwd='', empty=False, text=''):
    # queries the user for a passphrase if neccessary, and
    # returns a scrypted key of length l
    global _prev_passphrase
    if not pwd:
        pwd2 = not pwd
        if _prev_passphrase:
            print >>sys.stderr, "press enter to reuse the previous passphrase"
        while pwd != pwd2 or (not empty and not pwd.strip()):
            pwd = getpass.getpass('1/2 %s Passphrase: ' % text)
            if len(pwd.strip()):
                pwd2 = getpass.getpass('2/2 %s Repeat passphrase: ' % text)
            elif _prev_passphrase is not None:
                pwd = _prev_passphrase
                break
    if pwd.strip():
        _prev_passphrase = pwd
        return scrypt.hash(pwd, scrypt_salt)[:l]

def encrypt(msg, recipients=None, stream=False, pwd=None, self=None, k=None):
    # encrypts msg
    if not recipients:
        if stream:
            nonce = nacl.randombytes(nacl.crypto_stream_NONCEBYTES)
            if not k: k = getkey(nacl.crypto_stream_KEYBYTES, pwd=pwd)
            return ('s', nonce, nacl.crypto_stream_xor(msg, nonce, k))
        nonce = nacl.randombytes(nacl.crypto_secretbox_NONCEBYTES)
        if not k: k = getkey(nacl.crypto_secretbox_KEYBYTES, pwd=pwd)
        return ('c', nonce, nacl.crypto_secretbox(msg, nonce, k))
    sk = self.cs
    mk = k or nacl.randombytes(nacl.crypto_stream_KEYBYTES)
    c=[]
    for r in recipients:
        nonce = nacl.randombytes(nacl.crypto_box_NONCEBYTES)
        c.append((nonce, nacl.crypto_box(mk, nonce, r.cp, sk)))
    nonce = nacl.randombytes(nacl.crypto_secretbox_NONCEBYTES)
    return ('a', nonce, c, nacl.crypto_secretbox(msg, nonce, mk))

def decrypt(pkt, self=None, pwd=None, basedir=None, k=None):
    if pkt[0]=='s':
        # stream
        if not k:
            if not pwd: pwd = getpass.getpass('Passphrase for decrypting: ')
            k = scrypt.hash(pwd, scrypt_salt)[:nacl.crypto_secretbox_KEYBYTES]

        return nacl.crypto_stream_xor(pkt[2], pkt[1], k)
    if pkt[0]=='c':
        # symmetric
        if not k:
            if not pwd: pwd = getpass.getpass('Passphrase for decrypting: ')
            k = scrypt.hash(pwd, scrypt_salt)[:nacl.crypto_secretbox_KEYBYTES]

        return nacl.crypto_secretbox_open(pkt[2], pkt[1], k)

    sk = self.cs
    source = None
    mk = None
    for nonce, ck in pkt[2]:
        for keys in getpkeys(basedir=basedir):
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
    signing_key = self.ms if master else self.ss
    return nacl.crypto_sign(msg, signing_key)

def verify(msg, basedir=defaultbase, master=False):
    for keys in getpkeys(basedir=basedir):
        try:
            verifying_key = keys.mp if master else keys.sp
            return keys.name, nacl.crypto_sign_open(msg, verifying_key)
        except ValueError: pass

def encrypt_handler(infile, outfile=None, recipient=None, self=None, basedir=None):
    with open(infile,'r') as fd:
        msg=fd.read()
    output_filename = outfile if outfile else infile + '.pbp'
    with file(output_filename, 'w') as fd:
        if recipient and self:
            # let's do public key encryption
            type, nonce, r, cipher = encrypt(msg,
                                             recipients=[Identity(x, basedir=basedir)
                                                         for x
                                                         in recipient],
                                             self=Identity(self, basedir=basedir))
            if type != 'a':
                raise ValueError
            fd.write(struct.pack("B", ASYM_CIPHER))
            fd.write(nonce)
            fd.write(struct.pack("L", len(r)))
            for rnonce, ct in r:
                fd.write(rnonce)
                fd.write(struct.pack("B", len(ct)))
                fd.write(ct)
            fd.write(cipher)
        else:
            # let's do symmetric crypto
            type, nonce, cipher = encrypt(msg)
            # until we pass a param to encrypt above, it will always be block cipher
            if type == 'c':
                fd.write(struct.pack("B", BLOCK_CIPHER))
                fd.write(nonce)
                fd.write(cipher)
            elif type == 's':
                # use the stream cipher
                fd.write(struct.pack("B", STREAM_CIPHER))
                fd.write(nonce)
                fd.write(cipher)
            else:
                raise ValueError

def decrypt_handler(infile, outfile=None, self=None, basedir=None):
    with open(infile,'r') as fd:
        type=struct.unpack('B',fd.read(1))[0]
        # asym
        if type == ASYM_CIPHER:
            if not self:
                print >>sys.stderr, "Error: need to specify your own key using the --self param"
                raise ValueError
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
                                  basedir=basedir,
                                  self=Identity(self, basedir=basedir)) or ('', 'decryption failed')
            if sender:
                if not outfile:
                    print msg
                else:
                    with open(outfile,'w') as fd:
                        fd.write(msg)
                print >>sys.stderr, 'good message from', sender
            else:
                print >>sys.stderr, msg
            return

        # sym
        elif type == BLOCK_CIPHER:
            nonce = fd.read(nacl.crypto_secretbox_NONCEBYTES)
            msg = decrypt(('c', nonce, fd.read()))

        # stream
        elif type == STREAM_CIPHER:
            nonce = fd.read(nacl.crypto_stream_NONCEBYTES)
            msg = decrypt(('s', nonce, fd.read()))

        if len(msg):
            if not outfile:
                print msg
            else:
                with open(outfile,'w') as fd:
                    fd.write(msg)
        else:
            print >>sys.stderr,  'decryption failed'

def sign_handler(infile, outfile=None, self=None, basedir=None):
    with open(infile,'r') as fd:
        data = fd.read()
    with open(outfile or infile+'.sig','w') as fd:
        fd.write(sign(data, self=Identity(self, basedir=basedir)))

def verify_handler(infile, outfile=None, basedir=None):
    with open(infile,'r') as fd:
        data = fd.read()
    sender, msg = verify(data, basedir=basedir) or ('', 'verification failed')
    if len(sender)>0:
        if outfile:
            with open(outfile,'w') as fd:
                fd.write(msg)
        else:
            print msg
        print >>sys.stderr, "good message from", sender
    else:
        print >>sys.stderr, msg

def keysign_handler(infile, name=None, self=None, basedir=None):
    fname = get_pk_filename(basedir, name)
    with open(fname,'r') as fd:
        data = fd.read()
    with open(fname+'.sig','a') as fd:
        sig = sign(data,
                   self=Identity(self, basedir=basedir),
                   master=True)
        fd.write(sig[:32]+sig[-32:])

def keycheck_handler(name=None, basedir=None):
    fname = get_pk_filename(basedir, name)
    with open(fname,'r') as fd:
        pk = fd.read()
    sigs=[]
    with open(fname+".sig",'r') as fd:
        sigdat=fd.read()
    i=0
    while i<len(sigdat)/64:
        res = verify(sigdat[i*64:i*64+32]+pk+sigdat[i*64+32:i*64+64],
                     basedir=basedir,
                     master=True)
        if res:
            sigs.append(res[0])
        i+=1
    print >>sys.stderr, 'good signatures on', name, 'from', ', '.join(sigs)

def save_fwd(data, self, recipient, basedir):
    fname="%s/sk/.%s/%s" % (basedir, self.name, recipient)
    nonce = nacl.randombytes(nacl.crypto_box_NONCEBYTES)
    with open(fname,'w') as fd:
        fd.write(nonce)
        fd.write(nacl.crypto_box(data, nonce, self.cp, self.cs))

def load_fwd(self, recipient, basedir):
    mynext = myprev = peer = ('\0' * nacl.crypto_secretbox_KEYBYTES)
    keyfdir="%s/sk/.%s" % (basedir, self.name)
    if not os.path.exists(keyfdir):
        os.mkdir(keyfdir)
        return (mynext, myprev, peer)
    keyfname='%s/%s' % (keyfdir, recipient)
    if not os.path.exists(keyfname):
        return (mynext, myprev, peer)
    with open(keyfname,'r') as fd:
        nonce = fd.read(nacl.crypto_box_NONCEBYTES)
        plain =  nacl.crypto_box_open(fd.read(), nonce, self.cp, self.cs)
    return (plain[:nacl.crypto_secretbox_KEYBYTES],
            plain[nacl.crypto_secretbox_KEYBYTES:nacl.crypto_secretbox_KEYBYTES*2],
            plain[nacl.crypto_secretbox_KEYBYTES*2:nacl.crypto_secretbox_KEYBYTES*3])

def fwd_encrypt_handler(infile, outfile=None, recipient=None, self=None, basedir=None):
    output_filename = outfile if outfile else infile + '.pbp'
    self=Identity(self, basedir=basedir)
    mynext, myprev, peer = load_fwd(self,recipient[0], basedir)
    oldnext = mynext
    while mynext == ('\0' * nacl.crypto_secretbox_KEYBYTES):
        mynext=nacl.randombytes(nacl.crypto_secretbox_KEYBYTES)
    if oldnext != mynext:
        save_fwd(''.join((mynext, myprev, peer)), self, recipient[0], basedir)

    with open(infile,'r') as fd:
        msg=fd.read()

    if peer == ('\0' * nacl.crypto_secretbox_KEYBYTES):
        # encrypt using public key
        type, nonce, r, cipher = encrypt(mynext+msg,
                                         recipients=[Identity(recipient[0], basedir=basedir)],
                                         self=self)
        with open(output_filename, 'w') as fd:
            fd.write(nonce)
            fd.write(r[0][0])
            fd.write(struct.pack("B",len(r[0][1])))
            fd.write(r[0][1])
            fd.write(cipher)
    else:
        # encrypt using old fwd key
        type, nonce, cipher = encrypt(mynext+msg, k=peer)
        with open(output_filename, 'w') as fd:
            fd.write(nonce)
            fd.write(cipher)

def fwd_decrypt_handler(infile, outfile=None, recipient=None, self=None, basedir=None):
    self=Identity(self, basedir=basedir)
    mynext, myprev, peer = load_fwd(self,recipient[0], basedir)

    if mynext == ('\0' * nacl.crypto_secretbox_KEYBYTES):
        with open(infile,'r') as fd:
            nonce = fd.read(nacl.crypto_secretbox_NONCEBYTES)
            rnonce=fd.read(nacl.crypto_box_NONCEBYTES)
            ct = fd.read(struct.unpack('B',fd.read(1))[0])
            res = decrypt(('a',
                           nonce,
                           [(rnonce,ct)],
                           fd.read()),
                          basedir=basedir,
                          self=self)
        if not res:
            die("could not decrypt with public key")

        peer = res[1][:nacl.crypto_secretbox_KEYBYTES]
        if not outfile:
            print res[1][nacl.crypto_secretbox_KEYBYTES:]
        else:
            with open(outfile, 'w') as fd:
                fd.write(res[1][nacl.crypto_secretbox_KEYBYTES:])
    else:
        newkey=False
        with open(infile,'r') as fd:
            nonce = fd.read(nacl.crypto_secretbox_NONCEBYTES)
            msg = fd.read()
            try:
                res = decrypt(('c', nonce, msg), k=mynext )
                newkey = True
            except ValueError:
                res = decrypt(('c', nonce, msg), k=myprev )
            if not res:
                die("could not decrypt with fwd key")

        if newkey:
            myprev = mynext
            mynext=nacl.randombytes(nacl.crypto_secretbox_KEYBYTES)
            while mynext == ('\0' * nacl.crypto_secretbox_KEYBYTES):
                mynext=nacl.randombytes(nacl.crypto_secretbox_KEYBYTES)
        peer = res[:nacl.crypto_secretbox_KEYBYTES]
        if not outfile:
            print res[nacl.crypto_secretbox_KEYBYTES:]
        else:
            with open(outfile, 'w') as fd:
                fd.write(res[nacl.crypto_secretbox_KEYBYTES:])
    save_fwd(''.join((mynext, myprev, peer)), self, recipient[0], basedir)

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
    group.add_argument('--fcrypt',      '-e',  dest='action', action='store_const', const='e',help="encrypts a message using PFS to a peer")
    group.add_argument('--fdecrypt',    '-E',  dest='action', action='store_const', const='E',help="decrypts a message using PFS to a peer")

    parser.add_argument('--recipient',  '-r', action='append', help="designates a recipient for public key encryption")
    parser.add_argument('--name',       '-n', help="sets the name for a new key")
    parser.add_argument('--basedir',    '-b', '--base-dir', help="designates a recipient for public key encryption", default=defaultbase)
    parser.add_argument('--self',       '-S', help="sets your own key")
    parser.add_argument('--infile',     '-i', help="file to operate on")
    parser.add_argument('--armor',      '-a', action='store_true', help="ascii armors the output [TODO]")
    parser.add_argument('--outfile',    '-o', help="file to output to")
    opts=parser.parse_args()

    opts.basedir=os.path.expandvars( os.path.expanduser(opts.basedir))
    # Generate key
    if opts.action=='g':
        if not opts.name:
            die("Error: need to specify a Name for the key using the -n param")
        Identity(opts.name, create=True, basedir=opts.basedir)

    # list public keys
    elif opts.action=='l':
        for i in getpkeys(opts.basedir):
            print ('valid' if i.valid > datetime.datetime.utcnow() > i.created
                   else 'invalid'), i.keyid(), i.name

    # list secret keys
    elif opts.action=='L':
        for i in getskeys(opts.basedir):
            print ('valid' if i.valid > datetime.utcdatetime.now() > i.created
                   else 'invalid'), i.keyid(), i.name

    # encrypt
    elif opts.action=='c':
        if not opts.infile:
            die("Error: need to specify a file to operate on using the --in param")
        if opts.recipient and not opts.self:
            die("Error: need to specify your own key using the --self param")
        elif not opts.recipient and opts.self:
            die("Error: need to specify the recipient key using the --recipient param")
        encrypt_handler(infile=opts.infile,
                        outfile=opts.outfile,
                        recipient=opts.recipient,
                        self=opts.self,
                        basedir=opts.basedir)

    # decrypt
    elif opts.action=='d':
        if not opts.infile:
            die("Error: need to specify a file to operate on using the --in param")
        decrypt_handler(infile=opts.infile,
                        outfile=opts.outfile,
                        self=opts.self,
                        basedir=opts.basedir)

    # sign
    elif opts.action=='s':
        if not opts.infile:
            die("Error: need to specify a file to operate on using the --in param")
        if not opts.self:
            die("Error: need to specify your own key using the --self param")
        sign_handler(infile=opts.infile,
                     outfile=opts.outfile,
                     self=opts.self,
                     basedir=opts.basedir)

    # verify
    elif opts.action=='v':
        if not opts.infile:
            die("Error: need to specify a file to operate on using the --in param")
        verify_handler(infile=opts.infile,
                     outfile=opts.outfile,
                     basedir=opts.basedir)

    # key sign
    elif opts.action=='m':
        if not opts.name:
            die("Error: need to specify a key to operate on using the --name param")
        if not opts.self:
            die("Error: need to specify your own key using the --self param")
        keysign_handler(infile=opts.infile,
                        name=opts.name,
                        self=opts.self,
                        basedir=opts.basedir)

    # lists signatures owners on public keys
    elif opts.action=='C':
        if not opts.name:
            die("Error: need to specify a key to operate on using the --name param")
        keycheck_handler(name=opts.name,
                         basedir=opts.basedir)

    # forward encrypt
    elif opts.action=='e':
        if not opts.infile:
            die("Error: need to specify a file to "
                "operate on using the --in param")
        if not opts.recipient:
            die("Error: need to specify a recipient to "
                "operate on using the --recipient param")
        if len(opts.recipient)>1:
            die("Error: you can only PFS encrypt to one recipient.")
        if not opts.self:
            # TODO could try to find out this automatically if non-ambiguous
            die("Error: need to specify your own key using the --self param")
        fwd_encrypt_handler(opts.infile,
                        outfile=opts.outfile,
                        recipient=opts.recipient,
                        self=opts.self,
                        basedir=opts.basedir)

    # forward decrypt
    elif opts.action=='E':
        if not opts.infile:
            die("Error: need to specify a file to "
                "operate on using the --in param")
        if not opts.recipient:
            die("Error: need to specify a recipient to "
                "operate on using the --recipient param")
        if len(opts.recipient)>1:
            die("Error: you can only PFS decrypt from one recipient.")
        if not opts.self:
            # TODO could try to find out this automatically if non-ambiguous
            die("Error: need to specify your own key using the --self param")
        fwd_decrypt_handler(opts.infile,
                            outfile=opts.outfile,
                            recipient=opts.recipient,
                            self=opts.self,
                            basedir=opts.basedir)

def die(msg):
    print >>sys.stderr, msg
    sys.exit(1)

if __name__ == '__main__':
    #__test()
    main()
