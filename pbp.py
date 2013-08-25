#!/usr/bin/env python
import nacl, scrypt # external dependencies
import argparse, os, stat,  getpass, datetime, sys, struct, binascii
from itertools import imap
from utils import split_by_n, b85encode, b85decode
import chaining, identity

ASYM_CIPHER = 5
BLOCK_CIPHER = 23
SIGPREFIX = '\nnacl-'
BLOCK_SIZE = 1024*1024

defaultbase='~/.pbp'
scrypt_salt = 'qa~t](84z<1t<1oz:ik.@IRNyhG=8q(on9}4#!/_h#a7wqK{Nt$T?W>,mt8NqYq&6U<GB1$,<$j>,rSYI2GRDd:Bcm'

_prev_passphrase = ''

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

def encrypt(msg, pwd=None, k=None):
    nonce = nacl.randombytes(nacl.crypto_secretbox_NONCEBYTES)
    if not k: k = getkey(nacl.crypto_secretbox_KEYBYTES, pwd=pwd)
    return (nonce, nacl.crypto_secretbox(msg, nonce, k))

def decrypt(pkt, pwd=None, basedir=None, k=None):
    # symmetric
    if not k:
        if not pwd:
            pwd = getpass.getpass('Passphrase for decrypting: ')
        k =  scrypt.hash(pwd, scrypt_salt)[:nacl.crypto_secretbox_KEYBYTES]
    return nacl.crypto_secretbox_open(pkt[1], pkt[0], k)

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
        me = identity.Identity(self, basedir=basedir)
        peerkeys = me.keyencrypt(key, recipients=[identity.Identity(x, basedir=basedir)
                                                  for x
                                                  in recipient])
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
    while len(buf)>0:
        nonce, cipher = encrypt(buf, k=key)
        outfd.write(nonce)
        outfd.write(cipher)
        buf = fd.read(BLOCK_SIZE)

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
        me = identity.Identity(self, basedir=basedir)
        sender, key = me.keydecrypt(r)
        if sender:
            print >>sys.stderr, 'good key from', sender
        else:
            print >>sys.stderr, 'decryption failed'
    # sym
    elif type == BLOCK_CIPHER:
        pwd = getpass.getpass('Passphrase for decrypting: ')
        key =  scrypt.hash(pwd, scrypt_salt)[:nacl.crypto_secretbox_KEYBYTES]
    else:
        print >>sys.stderr,  'decryption failed'

    if key:
        nonce = fd.read(nacl.crypto_secretbox_NONCEBYTES)
        while len(nonce) == nacl.crypto_secretbox_NONCEBYTES:
            buf = fd.read(BLOCK_SIZE)
            if len(buf) == 0:
                print >>sys.stderr, 'decryption failed'
                break
            outfd.write(decrypt((nonce, buf), k = key))
            nonce = fd.read(nacl.crypto_secretbox_NONCEBYTES)
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
    for block in fd.read(BLOCK_SIZE):
        state = nacl.crypto_generichash_update(state, block)
        outfd.write(block)
    hashsum = nacl.crypto_generichash_final(state)

    # sign hashsum
    sig = identity.Identity(self, basedir=basedir).sign(hashsum)[:nacl.crypto_sign_BYTES]
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
    block = fd.read(BLOCK_SIZE/2)
    while len(block)>0:
        # use two half blocks, to overcome
        # sigs spanning block boundaries
        if len(block)==(BLOCK_SIZE/2):
            next=fd.read(BLOCK_SIZE/2)
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

    sender, hashsum1 = identity.verify(sig+hashsum, basedir=basedir) or ([], '')
    if len(sender)>0 and hashsum == hashsum1:
        print >>sys.stderr, "good message from", sender
    else:
        print >>sys.stderr, 'verification failed'

    if fd != sys.stdin: fd.close()
    if outfd != sys.stdout: outfd.close()

def keysign_handler(name=None, self=None, basedir=None):
    fname = identity.get_pk_filename(basedir, name)
    with open(fname,'r') as fd:
        data = fd.read()
    with open(fname+'.sig','a') as fd:
        sig = identity.Identity(self, basedir=basedir).sign(data, master=True)
        fd.write(sig[:nacl.crypto_sign_BYTES])

def export_handler(self, basedir=None):
    keys = identity.Identity(self, basedir=basedir)
    pkt = keys.sign(keys.mp+keys.cp+keys.sp+keys.name, master=True)
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
    peer = identity.Identity(name, basedir=basedir)
    peer.mp = mp
    peer.cp = keys[nacl.crypto_sign_PUBLICKEYBYTES:nacl.crypto_sign_PUBLICKEYBYTES*2]
    peer.sp = keys[nacl.crypto_sign_PUBLICKEYBYTES*2:nacl.crypto_sign_PUBLICKEYBYTES*3]
    # TODO check if key exists, then ask for confirmation of pk overwrite
    peer.save()
    print 'Success: imported public keys for', name

def keycheck_handler(name=None, basedir=None):
    fname = identity.get_pk_filename(basedir, name)
    with open(fname,'r') as fd:
        pk = fd.read()
    sigs=[]
    with open(fname+".sig",'r') as fd:
        sigdat=fd.read()
    i=0
    while i<len(sigdat)/64:
        res = identity.verify(sigdat[i*64:i*64+32]+pk+sigdat[i*64+32:i*64+64],
                              basedir=basedir,
                              master=True)
        if res:
            sigs.append(res[0])
        i+=1
    print >>sys.stderr, 'good signatures on', name, 'from', ', '.join(sigs)

def chaining_encrypt_handler(infile=None, outfile=None, recipient=None, self=None, basedir=None, armor=False):
    if not infile: infile = sys.stdin
    output_filename = outfile if outfile else infile + '.pbp'
    ctx=chaining.ChainingContext(self, recipient, basedir)
    ctx.load()
    # TODO buffered
    with open(infile, 'r') as inp:
        msg=inp.read()
    cipher, nonce = ctx.send(msg)
    with open(output_filename, 'w') as fd:
        fd.write(nonce)
        fd.write(cipher)
    ctx.save()

def chaining_decrypt_handler(infile=None, outfile=None, recipient=None, self=None, basedir=None):
    if not infile: infile = sys.stdin
    ctx=chaining.ChainingContext(self, recipient, basedir)
    ctx.load()
    # TODO buffered
    with open(infile,'r') as fd:
        nonce = fd.read(nacl.crypto_secretbox_NONCEBYTES)
        ct = fd.read()
    msg = ctx.receive(ct,nonce)
    if not outfile:
        print msg
    else:
        with open(outfile, 'w') as fd:
            fd.write(msg)
    ctx.save()

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
    group.add_argument('--export-key',  '-x',  dest='action', action='store_const', const='x',help="export public key")
    group.add_argument('--import-key',  '-X',  dest='action', action='store_const', const='X',help="import public key")
    group.add_argument('--check-sigs',  '-C',  dest='action', action='store_const', const='C',help="lists all known sigs on a public key")
    group.add_argument('--fcrypt',      '-e',  dest='action', action='store_const', const='e',help="encrypts a message using PFS to a peer")
    group.add_argument('--fdecrypt',    '-E',  dest='action', action='store_const', const='E',help="decrypts a message using PFS to a peer")

    parser.add_argument('--recipient',  '-r', action='append', help="designates a recipient for public key encryption")
    parser.add_argument('--name',       '-n', help="sets the name for a new key")
    parser.add_argument('--basedir',    '-b', '--base-dir', help="designates a recipient for public key encryption", default=defaultbase)
    parser.add_argument('--self',       '-S', help="sets your own key")
    parser.add_argument('--infile',     '-i', help="file to operate on")
    parser.add_argument('--armor',      '-a', action='store_true', help="ascii armors the output")
    parser.add_argument('--outfile',    '-o', help="file to output to")
    opts=parser.parse_args()

    opts.basedir=os.path.expandvars( os.path.expanduser(opts.basedir))
    # Generate key
    if opts.action=='g':
        ensure_name_specified(opts)
        identity.Identity(opts.name, create=True, basedir=opts.basedir)

    # list public keys
    elif opts.action=='l':
        for i in getpkeys(opts.basedir):
            print ('valid' if i.valid > datetime.datetime.utcnow() > i.created
                   else 'invalid'), i.keyid(), i.name

    # list secret keys
    elif opts.action=='L':
        for i in getskeys(opts.basedir):
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

def die(msg):
    print >>sys.stderr, msg
    sys.exit(1)

if __name__ == '__main__':
    #__test()
    main()
