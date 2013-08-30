#!/usr/bin/env python2
import pysodium as nacl, scrypt # external dependencies
import argparse, os, stat,  getpass, datetime, sys, struct, binascii
from itertools import imap
from utils import split_by_n, b85encode, b85decode, lockmem
from SecureString import clearmem
import chaining, publickey

ASYM_CIPHER = 5
BLOCK_CIPHER = 23
SIGPREFIX = '\nnacl-'
BLOCK_SIZE = 1024*1024

defaultbase='~/.pbp'
scrypt_salt = 'qa~t](84z<1t<1oz:ik.@IRNyhG=8q(on9}4#!/_h#a7wqK{Nt$T?W>,mt8NqYq&6U<GB1$,<$j>,rSYI2GRDd:Bcm'

_prev_passphrase = ''

def getkey(l, pwd='', empty=False, text=''):
    # queries the user twice for a passphrase if neccessary, and
    # returns a scrypted key of length l
    global _prev_passphrase
    clearpwd = (pwd.strip()=='')
    pwd2 = not pwd
    if not pwd:
        if _prev_passphrase:
            print >>sys.stderr, "press enter to reuse the previous passphrase"
        while pwd != pwd2 or (not empty and not pwd.strip()):
            pwd = getpass.getpass('1/2 %s Passphrase: ' % text)
            if pwd.strip():
                pwd2 = getpass.getpass('2/2 %s Repeat passphrase: ' % text)
            elif _prev_passphrase is not None:
                pwd = _prev_passphrase
                break
    #if isinstance(pwd2, str):
        #clearmem(pwd2)
    if pwd.strip():
        _prev_passphrase = pwd
        key = scrypt.hash(pwd, scrypt_salt)[:l]
        #if clearpwd: clearmem(pwd)
        return key

def encrypt(msg, pwd=None, k=None):
    # symmetric
    nonce = nacl.randombytes(nacl.crypto_secretbox_NONCEBYTES)
    cleark = (k is None)
    if not k:
        k = getkey(nacl.crypto_secretbox_KEYBYTES, pwd=pwd)
    ciphertext = nacl.crypto_secretbox(msg, nonce, k)
    if cleark: clearmem(k)
    return (nonce, ciphertext)

def decrypt(pkt, pwd=None, basedir=None, k=None):
    # symmetric
    cleark = (pwd is None)
    clearpwd = (k is None)
    if not k:
        if not pwd:
            pwd = getpass.getpass('Passphrase for decrypting: ')
        k =  scrypt.hash(pwd, scrypt_salt)[:nacl.crypto_secretbox_KEYBYTES]
        if clearpwd: clearmem(pwd)
    res = nacl.crypto_secretbox_open(pkt[1], pkt[0], k)
    if cleark: clearmem(k)
    return res

def encrypt_handler(infile=None, outfile=None, recipient=None, self=None, basedir=None):
    if not infile or infile == '-':
        fd = sys.stdin
    else:
        fd = open(infile,'r')

    if outfile == '-':
        outfd = sys.stdout
    else:
        outfd = open(outfile or infile+'.pbp','w')

    if recipient and self:
        # let's do public key encryption
        key = nacl.randombytes(nacl.crypto_secretbox_KEYBYTES)
        me = publickey.Identity(self, basedir=basedir)
        peerkeys = me.keyencrypt(key, recipients=[publickey.Identity(x, basedir=basedir)
                                                  for x
                                                  in recipient])
        me.clear()
        outfd.write(struct.pack("B", ASYM_CIPHER))
        outfd.write(struct.pack(">L", len(peerkeys)))
        for rnonce, ct in peerkeys:
            outfd.write(rnonce)
            outfd.write(struct.pack("B", len(ct)))
            outfd.write(ct)
    else:
        # let's do symmetric crypto
        key = getkey(nacl.crypto_secretbox_KEYBYTES)
        outfd.write(struct.pack("B", BLOCK_CIPHER))

    buf = fd.read(BLOCK_SIZE)
    while buf:
        nonce, cipher = encrypt(buf, k=key)
        outfd.write(nonce)
        outfd.write(cipher)
        buf = fd.read(BLOCK_SIZE)
    clearmem(key)

    if infile != sys.stdin: fd.close()
    if outfile != sys.stdout: outfd.close()

def decrypt_handler(infile=None, outfile=None, self=None, basedir=None):
    if not infile or infile == '-':
        fd = sys.stdin
    else:
        fd = open(infile,'r')
    if not outfile or outfile == '-':
        outfd = sys.stdout
    else:
        outfd = open(outfile,'w')

    key = None
    type=struct.unpack('B',fd.read(1))[0]
    # asym
    if type == ASYM_CIPHER:
        if not self:
            print >>sys.stderr, "Error: need to specify your own key using the --self param"
            raise ValueError
        size = struct.unpack('>L',fd.read(4))[0]
        r = []
        for _ in xrange(size):
            rnonce = fd.read(nacl.crypto_box_NONCEBYTES)
            ct = fd.read(struct.unpack('B', fd.read(1))[0])
            r.append((rnonce,ct))
        me = publickey.Identity(self, basedir=basedir)
        me.clear()
        sender, key = me.keydecrypt(r)
        if sender:
            print >>sys.stderr, 'good key from', sender
        else:
            print >>sys.stderr, 'decryption failed'
    # sym
    elif type == BLOCK_CIPHER:
        pwd = getpass.getpass('Passphrase for decrypting: ')
        key =  scrypt.hash(pwd, scrypt_salt)[:nacl.crypto_secretbox_KEYBYTES]
        clearmem(pwd)
    else:
        print >>sys.stderr,  'decryption failed'

    if key:
        nonce = fd.read(nacl.crypto_secretbox_NONCEBYTES)
        while len(nonce) == nacl.crypto_secretbox_NONCEBYTES:
            buf = fd.read(BLOCK_SIZE)
            if not buf:
                print >>sys.stderr, 'decryption failed'
                break
            outfd.write(decrypt((nonce, buf), k = key))
            nonce = fd.read(nacl.crypto_secretbox_NONCEBYTES)
        clearmem(key)
        if 0 < len(nonce) < nacl.crypto_secretbox_NONCEBYTES:
            print >>sys.stderr, 'decryption failed'

    if infile != sys.stdin: fd.close()
    if outfile != sys.stdout: outfd.close()

def sign_handler(infile=None, outfile=None, self=None, basedir=None, armor=False):
    if not infile or infile == '-':
        fd = sys.stdin
    else:
        fd = open(infile,'r')

    if (not outfile and armor) or outfile == '-':
        outfd = sys.stdout
    else:
        outfd = open(outfile or infile+'.sig','w')

    # calculate hash sum of data
    state = nacl.crypto_generichash_init()
    while True:
        block =  fd.read(BLOCK_SIZE)
        if not block.strip(): break
        state = nacl.crypto_generichash_update(state, block)
        outfd.write(block)
    hashsum = nacl.crypto_generichash_final(state)

    me = publickey.Identity(self, basedir=basedir)
    # sign hashsum
    sig = me.sign(hashsum)[:nacl.crypto_sign_BYTES]
    me.clear()
    if armor:
        signed = "%s%s" % (SIGPREFIX, b85encode(sig))
    if armor and not outfile:
        sys.stdout.write(signed)
    else:
        outfd.write(sig)

    if fd != sys.stdin: fd.close()
    if outfd != sys.stdout: outfd.close()

def verify_handler(infile=None, outfile=None, basedir=None):
    if not infile or infile == '-':
        fd = sys.stdin
    else:
        fd = open(infile,'r')
    if not outfile or outfile == '-':
        outfd = sys.stdout
    else:
        outfd = open(outfile,'w')

    # calculate hash sum of data
    state = nacl.crypto_generichash_init()
    block = fd.read(int(BLOCK_SIZE/2))
    while block:
        # use two half blocks, to overcome
        # sigs spanning block boundaries
        if len(block)==(BLOCK_SIZE/2):
            next=fd.read(int(BLOCK_SIZE/2))
        else: next=''

        fullblock = "%s%s" % (block, next)
        sigoffset = fullblock.rfind(SIGPREFIX)

        if 0 <= sigoffset <= (BLOCK_SIZE/2):
            sig = b85decode(fullblock[sigoffset+len(SIGPREFIX):])
            block = block[:sigoffset]
            next = ''
        elif len(fullblock)<(BLOCK_SIZE/2)+nacl.crypto_sign_BYTES:
            sig = fullblock[-nacl.crypto_sign_BYTES:]
            block = fullblock[:-nacl.crypto_sign_BYTES]
            next = ''
        state = nacl.crypto_generichash_update(state, block)
        if outfd: outfd.write(block)
        block = next
    hashsum = nacl.crypto_generichash_final(state)

    sender, hashsum1 = publickey.verify(sig+hashsum, basedir=basedir) or ([], '')
    if sender and hashsum == hashsum1:
        print >>sys.stderr, "good message from", sender
    else:
        print >>sys.stderr, 'verification failed'

    if fd != sys.stdin: fd.close()
    if outfd != sys.stdout: outfd.close()

def keysign_handler(name=None, self=None, basedir=None):
    fname = publickey.get_pk_filename(basedir, name)
    with open(fname,'r') as fd:
        data = fd.read()
    with open(fname+'.sig','a') as fd:
        me = publickey.Identity(self, basedir=basedir)
        sig = me.sign(data, master=True)
        if not sig:
            print >>sys.stderr, 'signature failed'
        me.clear()
        fd.write(sig[:nacl.crypto_sign_BYTES])

def keycheck_handler(name=None, basedir=None):
    fname = publickey.get_pk_filename(basedir, name)
    with open(fname,'r') as fd:
        pk = fd.read()
    sigs=[]
    with open(fname+".sig",'r') as fd:
        sigdat=fd.read()
    i=0
    csb = nacl.crypto_sign_BYTES
    while i<len(sigdat)/64:
        res = publickey.verify(sigdat[i*csb:(i+1)*csb]+pk,
                              basedir=basedir,
                              master=True)
        if res:
            sigs.append(res[0])
        i+=1
    print >>sys.stderr, 'good signatures on', name, 'from', ', '.join(sigs)

def export_handler(self, basedir=None):
    keys = publickey.Identity(self, basedir=basedir)
    pkt = keys.sign(keys.mp+keys.cp+keys.sp+keys.name, master=True)
    keys.clear()
    print b85encode(pkt)

def import_handler(infile=None, basedir=None):
    if not infile:
        b85 = sys.stdin.readline().strip()
    else:
        with file(infile) as fd:
            b85 = fd.readline().strip()
    pkt = b85decode(b85)
    mp = pkt[nacl.crypto_sign_BYTES:nacl.crypto_sign_BYTES+nacl.crypto_sign_PUBLICKEYBYTES]
    keys = nacl.crypto_sign_open(pkt, mp)
    if not keys:
        die("invalid key")
    name = keys[nacl.crypto_sign_PUBLICKEYBYTES*3:]
    peer = publickey.Identity(name, basedir=basedir)
    peer.mp = mp
    peer.cp = keys[nacl.crypto_sign_PUBLICKEYBYTES:nacl.crypto_sign_PUBLICKEYBYTES*2]
    peer.sp = keys[nacl.crypto_sign_PUBLICKEYBYTES*2:nacl.crypto_sign_PUBLICKEYBYTES*3]
    # TODO check if key exists, then ask for confirmation of pk overwrite
    peer.save()
    print 'Success: imported public keys for', name

def chaining_encrypt_handler(infile=None, outfile=None, recipient=None, self=None, basedir=None, armor=False):
    if not infile: infile = sys.stdin
    output_filename = outfile if outfile else infile + '.pbp'
    ctx=chaining.ChainingContext(self, recipient, basedir)
    ctx.load()
    inp = open(infile, 'r')
    msg=inp.read(BLOCK_SIZE)
    cipher, nonce = ctx.send(msg)
    fd = open(output_filename, 'w')
    while True:
        fd.write(nonce)
        fd.write(cipher)
        msg=inp.read(BLOCK_SIZE)
        if not msg: break
        cipher, nonce = ctx.encrypt(msg)
    ctx.save()
    ctx.clear()
    if not infile: inp.close()
    fd.close()

def chaining_decrypt_handler(infile=None, outfile=None, recipient=None, self=None, basedir=None):
    fd = sys.stdin if not infile else open(infile,'r')
    outfd = sys.stdout if not outfile else open(outfile, 'w')
    ctx=chaining.ChainingContext(self, recipient, basedir)
    ctx.load()
    blocklen=BLOCK_SIZE+(nacl.crypto_scalarmult_curve25519_BYTES*2)
    if ctx.out_k == ('\0' * nacl.crypto_scalarmult_curve25519_BYTES):
        nonce = fd.read(nacl.crypto_box_NONCEBYTES)
    else:
        nonce = fd.read(nacl.crypto_secretbox_NONCEBYTES)
    ct = fd.read(blocklen+16)
    msg = ctx.receive(ct,nonce)
    while True:
        outfd.write(msg)
        nonce = fd.read(nacl.crypto_secretbox_NONCEBYTES)
        if not nonce:
            break
        if len(nonce) != nacl.crypto_secretbox_NONCEBYTES:
            print >>sys.stderr, 'decryption failed'
            return
        ct = fd.read(BLOCK_SIZE+16)
        msg = ctx.decrypt(ct,nonce)
    ctx.save()
    ctx.clear()
    if infile: fd.close()
    if outfile: outfd.close()

def dh1_handler():
    exp = nacl.randombytes(nacl.crypto_scalarmult_curve25519_BYTES)
    public = nacl.crypto_scalarmult_curve25519_base(exp)
    print "public component", b85encode(public)
    print "secret exponent", b85encode(exp)
    clearmem(exp)

def dh2_handler(peer):
    exp = nacl.randombytes(nacl.crypto_scalarmult_curve25519_BYTES)
    public = nacl.crypto_scalarmult_curve25519_base(exp)
    print "public component", b85encode(public)
    secret = nacl.crypto_scalarmult_curve25519(exp, b85decode(peer))
    print "shared secret", b85encode(secret)
    clearmem(secret)
    clearmem(exp)

def dh3_handler(public, exp):
    secret = nacl.crypto_scalarmult_curve25519(b85decode(exp), b85decode(public))
    print "shared secret", b85encode(secret)
    clearmem(secret)

def random_stream_handler(outfile = None, size = None):
    bsize = 2**16
    outfd = sys.stdout if not outfile else open(outfile, 'w')
    if not size:
        while True:
            # write endlessly
            outfd.write(nacl.crypto_stream(bsize))
    i = 0
    size = long(size)
    while i <= size:
        if i+bsize <= size:
            outfd.write(nacl.crypto_stream(bsize))
            i+=bsize
        else:
            outfd.write(nacl.crypto_stream(size - i))
            break

def main():
    parser = argparse.ArgumentParser(description='pbp')
    group = parser.add_mutually_exclusive_group()
    group.add_argument('--gen-key',     '-g',  dest='action', action='store_const', const='g', help="generates a new key")
    group.add_argument('--encrypt',     '-c',  dest='action', action='store_const', const='c',help="encrypts")
    group.add_argument('--decrypt',     '-d',  dest='action', action='store_const', const='d',help="decrypts")
    group.add_argument('--sign',        '-s',  dest='action', action='store_const', const='s',help="signs")
    group.add_argument('--master-sign', '-m',  dest='action', action='store_const', const='m',help="signs keys with your masterkey")
    group.add_argument('--verify',      '-v',  dest='action', action='store_const', const='v',help="verifies")
    group.add_argument('--list',        '-l',  dest='action', action='store_const', const='l',help="lists public keys")
    group.add_argument('--list-secret', '-L',  dest='action', action='store_const', const='L',help="Lists secret keys")
    group.add_argument('--export-key',  '-x',  dest='action', action='store_const', const='x',help="export public key")
    group.add_argument('--import-key',  '-X',  dest='action', action='store_const', const='X',help="import public key")
    group.add_argument('--check-sigs',  '-C',  dest='action', action='store_const', const='C',help="lists all known sigs on a public key")
    group.add_argument('--fcrypt',      '-e',  dest='action', action='store_const', const='e',help="encrypts a message using PFS to a peer")
    group.add_argument('--fdecrypt',    '-E',  dest='action', action='store_const', const='E',help="decrypts a message using PFS to a peer")
    group.add_argument('--dh-start',    '-D1', dest='action', action='store_const', const='d1',help="initiates an ECDH key exchange")
    group.add_argument('--dh-respond',  '-D2', dest='action', action='store_const', const='d2',help="responds to an ECDH key request")
    group.add_argument('--dh-end',      '-D3', dest='action', action='store_const', const='d3',help="finalizes an ECDH key exchange")
    group.add_argument('--rand-stream', '-R',  dest='action', action='store_const', const='R',help="generate arbitrary random stream")

    parser.add_argument('--recipient',  '-r', action='append', help="designates a recipient for public key encryption")
    parser.add_argument('--name',       '-n', help="sets the name for a new key")
    parser.add_argument('--basedir',    '-b', '--base-dir', help="set the base directory for all key storage needs", default=defaultbase)
    parser.add_argument('--self',       '-S', help="sets your own key")
    parser.add_argument('--dh-param',   '-Dp',help="public parameter for ECDH key exchange")
    parser.add_argument('--dh-exp',     '-De',help="public parameter for ECDH key exchange")
    parser.add_argument('--size',       '-Rs',help="size of random stream to generate")
    parser.add_argument('--infile',     '-i', help="file to operate on")
    parser.add_argument('--armor',      '-a', action='store_true', help="ascii armors the output")
    parser.add_argument('--outfile',    '-o', help="file to output to")
    opts=parser.parse_args()

    opts.basedir=os.path.expandvars( os.path.expanduser(opts.basedir))
    # Generate key
    if opts.action=='g':
        ensure_name_specified(opts)
        publickey.Identity(opts.name, create=True, basedir=opts.basedir)

    # list public keys
    elif opts.action=='l':
        for i in publickey.get_public_keys(opts.basedir):
            print ('valid' if i.valid > datetime.datetime.utcnow() > i.created
                   else 'invalid'), i.keyid(), i.name

    # list secret keys
    elif opts.action=='L':
        for i in publickey.get_secret_keys(opts.basedir):
            print ('valid' if i.valid > datetime.datetime.utcnow() > i.created
                   else 'invalid'), i.keyid(), i.name

    # encrypt
    elif opts.action=='c':
        if opts.recipient or opts.self:
            ensure_self_specified(opts)
            ensure_recipient_specified(opts)
        encrypt_handler(infile=opts.infile,
                        outfile=opts.outfile,
                        recipient=opts.recipient,
                        self=opts.self,
                        basedir=opts.basedir)

    # decrypt
    elif opts.action=='d':
        decrypt_handler(infile=opts.infile,
                        outfile=opts.outfile,
                        self=opts.self,
                        basedir=opts.basedir)

    # sign
    elif opts.action=='s':
        ensure_self_specified(opts)
        sign_handler(infile=opts.infile,
                     outfile=opts.outfile,
                     self=opts.self,
                     armor=opts.armor,
                     basedir=opts.basedir)

    # verify
    elif opts.action=='v':
        verify_handler(infile=opts.infile,
                       outfile=opts.outfile,
                       basedir=opts.basedir)

    # key sign
    elif opts.action=='m':
        ensure_name_specified(opts)
        ensure_self_specified(opts)
        keysign_handler(name=opts.name,
                        self=opts.self,
                        basedir=opts.basedir)

    # lists signatures owners on public keys
    elif opts.action=='C':
        ensure_name_specified(opts)
        keycheck_handler(name=opts.name,
                         basedir=opts.basedir)

    # export public key
    elif opts.action=='x':
        ensure_self_specified(opts)
        export_handler(opts.self,
                       basedir=opts.basedir)
    # import public key
    elif opts.action=='X':
        import_handler(infile=opts.infile,
                       basedir=opts.basedir)

    # forward encrypt
    elif opts.action=='e':
        ensure_recipient_specified(opts)
        ensure_only_one_recipient(opts)
        # TODO could try to find out this automatically if non-ambiguous
        ensure_self_specified(opts)
        chaining_encrypt_handler(opts.infile,
                        outfile=opts.outfile,
                        recipient=opts.recipient[0],
                        self=opts.self,
                        armor=opts.armor,
                        basedir=opts.basedir)

    # forward decrypt
    elif opts.action=='E':
        ensure_recipient_specified(opts)
        ensure_only_one_recipient(opts)
        # TODO could try to find out this automatically if non-ambiguous
        ensure_self_specified(opts)
        chaining_decrypt_handler(opts.infile,
                            outfile=opts.outfile,
                            recipient=opts.recipient[0],
                            self=opts.self,
                            basedir=opts.basedir)
    # start ECDH
    elif opts.action=='d1':
        dh1_handler()
    # receive ECDH
    elif opts.action=='d2':
        ensure_dhparam_specified(opts)
        dh2_handler(opts.dh_param)
    # finish ECDH
    elif opts.action=='d3':
        ensure_dhparam_specified(opts)
        ensure_dhexp_specified(opts)
        dh3_handler(opts.dh_param, opts.dh_exp)

    elif opts.action=='R':
        ensure_size_good(opts)
        random_stream_handler(opts.outfile, opts.size)

def ensure_self_specified(opts):
    if not opts.self:
        die("Error: need to specify your own key using the --self param")

def ensure_name_specified(opts):
    if not opts.name:
        die("Error: need to specify a key to operate on using the --name param")

def ensure_recipient_specified(opts):
    if not opts.recipient:
        die("Error: need to specify a recipient to "
            "operate on using the --recipient param")

def ensure_only_one_recipient(opts):
    if len(opts.recipient) > 1:
        die("Error: you can only PFS decrypt from one recipient.")

def ensure_dhparam_specified(opts):
    if not opts.dh_param:
        die("Error: need to specify the ECDH public parameter using the -Dp param")

def ensure_dhexp_specified(opts):
    if not opts.dh_exp:
        die("Error: need to specify your secret ECDH exponent using the -De param")

def ensure_size_good(opts):
    if opts.size:
        fact = 1
        if opts.size[-1] == 'K':
            fact = 1024
            opts.size = opts.size[:-1]
        elif opts.size[-1] == 'M':
            fact = 1024 * 1024
            opts.size = opts.size[:-1]
        elif opts.size[-1] == 'G':
            fact = 1024 * 1024 * 1024
            opts.size = opts.size[:-1]
        elif opts.size[-1] == 'T':
            fact = 1024 * 1024 * 1024 * 1024
            opts.size = opts.size[:-1]
        try:
            opts.size = float(opts.size) * fact
        except:
            die("Error: need to specify an float after -Rs <float><[K|M|G|T]>")

def die(msg):
    print >>sys.stderr, msg
    sys.exit(1)

if __name__ == '__main__':
    lockmem()
    main()
    clearmem(_prev_passphrase)
