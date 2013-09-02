#!/usr/bin/env python2
import pysodium as nacl, scrypt # external dependencies
import getpass, sys, struct
from utils import b85encode, b85decode, lockmem
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
    # allows empty passphrases if empty == True
    # 'text' will be prepended to the password query
    # will not query for a password if pwd != ''
    global _prev_passphrase
    #clearpwd = (pwd.strip()=='')
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
    #   clearmem(pwd2)
    if pwd.strip():
        _prev_passphrase = pwd
        key = scrypt.hash(pwd, scrypt_salt)[:l]
        #if clearpwd: clearmem(pwd)
        return key

def encrypt(msg, pwd=None, k=None):
    # encrypts a message symmetrically using crypto_secretbox
    # k specifies an encryption key, which if not supplied, is derived from
    # pwd which is queried from the user, if also not specified.
    # returns a (nonce, ciphertext) tuple
    nonce = nacl.randombytes(nacl.crypto_secretbox_NONCEBYTES)
    cleark = (k is None)
    if not k:
        k = getkey(nacl.crypto_secretbox_KEYBYTES, pwd=pwd)
    ciphertext = nacl.crypto_secretbox(msg, nonce, k)
    if cleark: clearmem(k)
    return (nonce, ciphertext)

def decrypt(pkt, pwd=None, k=None, retries=3):
    # decrypts a message symmetrically using crypto_secretbox
    # pkt is a (nonce, ciphertext) tuple
    # k specifies an encryption key, which if not supplied, is derived from
    # pwd which is queried from the user, if also not specified.
    cleark = (pwd is None)
    clearpwd = (k is None)
    cnt=0
    res = None
    while cnt<retries:
        if not k:
            if not pwd:
                pwd = getpass.getpass('Passphrase for decrypting: ')
            k =  scrypt.hash(pwd, scrypt_salt)[:nacl.crypto_secretbox_KEYBYTES]
            if clearpwd: clearmem(pwd)
            pwd = None
        try:
            res = nacl.crypto_secretbox_open(pkt[1], pkt[0], k)
        except ValueError:
            cnt += 1
            if cleark: clearmem(k)
            k = None
            continue
        break
    if cleark: clearmem(k)
    if res:
        return res

def encrypt_handler(infile=None, outfile=None, recipient=None, self=None, basedir=None):
    # provides a high level function to do encryption of files
    # infile specifies the filename of the input file,
    #        if '-' or not specified it uses stdin
    # outfile specifies the filename of the output file, if not specified
    #         it uses the same filename with '.pbp' appended
    # recipient specifies the name of the recipient for using public key crypto
    # self specifies the sender for signing the message using pk crypto
    # basedir provides a root for the keystores needed for pk crypto
    # if both self and recipient is specified pk crypto is used, otherwise symmetric
    # this function also handles buffering.
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

    if fd != sys.stdin: fd.close()
    if outfd != sys.stdout: outfd.close()

def decrypt_handler(infile=None, outfile=None, self=None, basedir=None):
    # provides a high level function to do decryption of files
    # infile specifies the filename of the input file,
    #        if '-' or not specified it uses stdin
    # outfile specifies the filename of the output file, if not specified
    #         it uses the same filename with '.pbp' appended
    # self specifies the recipient of the message for using pk crypto
    # basedir provides a root for the keystores needed for pk crypto
    # if self is specified pk crypto is used, otherwise symmetric
    # this function also handles buffering.
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

    if fd != sys.stdin: fd.close()
    if outfd != sys.stdout: outfd.close()

def sign_handler(infile=None, outfile=None, self=None, basedir=None, armor=False):
    # provides a high level function to sign files
    # infile specifies the filename of the input file,
    #        if '-' or not specified it uses stdin
    # outfile specifies the filename of the output file,
    #         if unspecified but armor is, or if '-' or
    #         infile is unspecified, then it uses stdout
    #         otherwise it appends '.sig' to infile
    # armor instructs the function to output ascii 
    # self specifies the sender for signing the message
    # basedir provides a root for the keystores
    # this function also handles buffering.
    if not infile or infile == '-':
        fd = sys.stdin
    else:
        fd = open(infile,'r')

    if (not outfile and armor) or outfile == '-' or (not infile or infile == '-'):
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
        sig = "%s%s" % (SIGPREFIX, b85encode(sig))
    outfd.write(sig)

    if fd != sys.stdin: fd.close()
    if outfd != sys.stdout: outfd.close()

def verify_handler(infile=None, outfile=None, basedir=None):
    # provides a high level function to verify signed files
    # infile specifies the filename of the input file,
    #        if '-' or not specified it uses stdin
    # outfile specifies the filename of the output file,
    # basedir provides a root for the keystores
    # this function also handles buffering.
    if not infile or infile == '-':
        fd = sys.stdin
    else:
        fd = open(infile,'r')
    if outfile:
        if outfile == '-':
            outfd = sys.stdout
        else:
            outfd = open(outfile,'w')
    else:
        outfd = sys.stdout

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
    if fd != sys.stdin: fd.close()
    if outfd != sys.stdout: outfd.close()
    hashsum = nacl.crypto_generichash_final(state)

    sender, hashsum1 = publickey.verify(sig+hashsum, basedir=basedir) or ([], '')
    if sender and hashsum == hashsum1:
        return sender

def keysign_handler(name=None, self=None, basedir=None):
    # handles signing of keys using the master key
    # name is the key to be signed
    # self the signers name
    # basedir the root for the keystore
    fname = publickey.get_pk_filename(basedir, name)
    with open(fname,'r') as fd:
        data = fd.read()
    with open(fname+'.sig','a') as fd:
        me = publickey.Identity(self, basedir=basedir)
        sig = me.sign(data, master=True)
        if sig:
            me.clear()
            fd.write(sig[:nacl.crypto_sign_BYTES])
            return fname+'.sig'

def keycheck_handler(name=None, basedir=None):
    # handles verifying signatures of keys
    # name is the key to be verified
    # basedir the root for the keystore
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
    return sigs

def export_handler(self, basedir=None):
    # exports key self from basedir, outputs to stdout, key is ascii armored
    keys = publickey.Identity(self, basedir=basedir)
    pkt = keys.sign(keys.mp+keys.cp+keys.sp+keys.name, master=True)
    keys.clear()
    return b85encode(pkt)

def import_handler(infile=None, basedir=None):
    # imports ascii armored key from infile or stdin to basedir
    if not infile:
        b85 = sys.stdin.readline().strip()
    else:
        with file(infile) as fd:
            b85 = fd.readline().strip()
    pkt = b85decode(b85)
    mp = pkt[nacl.crypto_sign_BYTES:nacl.crypto_sign_BYTES+nacl.crypto_sign_PUBLICKEYBYTES]
    keys = nacl.crypto_sign_open(pkt, mp)
    if not keys:
        return
    name = keys[nacl.crypto_sign_PUBLICKEYBYTES*3:]
    peer = publickey.Identity(name, basedir=basedir)
    peer.mp = mp
    peer.cp = keys[nacl.crypto_sign_PUBLICKEYBYTES:nacl.crypto_sign_PUBLICKEYBYTES*2]
    peer.sp = keys[nacl.crypto_sign_PUBLICKEYBYTES*2:nacl.crypto_sign_PUBLICKEYBYTES*3]
    # TODO check if key exists, then ask for confirmation of pk overwrite
    peer.save()
    return name

def chaining_encrypt_handler(infile=None, outfile=None, recipient=None, self=None, basedir=None):
    # provides highlevel forward secure encryption send primitive for files
    # for details see doc/chaining-dh.txt
    # infile specifies the input file,
    # outfile the filename of the output,
    # self the sending parties name
    # recipient the receiving peers name
    # basedir the root directory used for key storage
    if not infile or infile == '-':
        inp = sys.stdin
    else:
        inp = open(infile,'r')
    if outfile == '-' or (not infile or infile == '-'):
        fd = sys.stdout
    else:
        fd = open(outfile or infile+'.pbp','w')

    ctx=chaining.ChainingContext(self, recipient, basedir)
    ctx.load()
    msg=inp.read(BLOCK_SIZE)
    cipher, nonce = ctx.send(msg)
    while True:
        fd.write(nonce)
        fd.write(cipher)
        msg=inp.read(BLOCK_SIZE)
        if not msg: break
        cipher, nonce = ctx.encrypt(msg)
    ctx.save()
    ctx.clear()
    if inp != sys.stdin: inp.close()
    if fd != sys.stdout: fd.close()

def chaining_decrypt_handler(infile=None, outfile=None, recipient=None, self=None, basedir=None):
    # provides highlevel forward secure deccryption receive primitive for files
    # for details see doc/chaining-dh.txt
    # infile specifies the input file,
    # outfile the filename of the output,
    # self the sending parties name
    # recipient the receiving peers name
    # basedir the root directory used for key storage
    if not infile or infile == '-':
        fd = sys.stdin
    else:
        fd = open(infile,'r')
    if outfile == '-' or (not infile or infile == '-'):
        outfd = sys.stdout
    else:
        outfd = open(outfile or infile+'.pbp','w')

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
    if fd != sys.stdin: fd.close()
    if outfd != sys.stdout: outfd.close()

def dh1_handler():
    # provides a high level interface to start a DH key exchange
    exp = nacl.randombytes(nacl.crypto_scalarmult_curve25519_BYTES)
    public = nacl.crypto_scalarmult_curve25519_base(exp)
    return (exp, public)

def dh2_handler(peer):
    # provides a high level interface to receive a DH key exchange
    # request peer contains the public component generated by the peer
    # when initiating an DH exchange
    exp = nacl.randombytes(nacl.crypto_scalarmult_curve25519_BYTES)
    public = nacl.crypto_scalarmult_curve25519_base(exp)
    secret = nacl.crypto_scalarmult_curve25519(exp, b85decode(peer))
    return (public, secret)

def dh3_handler(public, exp):
    # finishes the 3 step DH key exchange by combining the public
    # component of the peer, generated in the 2nd step by the peer,
    # using the exponent generated when the exchange was initiated.
    secret = nacl.crypto_scalarmult_curve25519(b85decode(exp), b85decode(public))
    return secret

def random_stream_handler(outfile = None, size = None):
    # generates a stream of 'size' or if 'size' unspecified then
    # infinite random bytes into outfile or stdout if outfile is
    # unspecified.
    bsize = 2**16
    outfd = sys.stdout if not outfile else open(outfile, 'w')
    if not size:
        while True:
            # infinite write
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

if __name__ == '__main__':
    from main import main
    lockmem()
    main()
    clearmem(_prev_passphrase)
