#!/usr/bin/env python2
import argparse, os, sys, datetime, binascii
from utils import b85encode, lockmem, split_by_n
from SecureString import clearmem
import publickey, pysodium as nacl
try:
    import pitchfork
    PITCHFORK=True
except: # ignore missing pitchfork
    PITCHFORK=False
from pbp import defaultbase, encrypt_handler, decrypt_handler, sign_handler
from pbp import verify_handler, keysign_handler, keycheck_handler, export_handler
from pbp import import_handler, chaining_encrypt_handler, chaining_decrypt_handler
from pbp import dh1_handler, dh2_handler, dh3_handler, mpecdh_start_handler, mpecdh_end_handler, random_stream_handler
from pbp import hash_handler

def main():
    # main command line handler for pbp
    parser = argparse.ArgumentParser(description='pbp')
    group = parser.add_mutually_exclusive_group()
    group.add_argument('--gen-key',     '-g',  dest='action', action='store_const', const='g', help="generates a new key")
    group.add_argument('--encrypt',     '-c',  dest='action', action='store_const', const='c',help="encrypts")
    group.add_argument('--decrypt',     '-d',  dest='action', action='store_const', const='d',help="decrypts")
    group.add_argument('--sign',        '-s',  dest='action', action='store_const', const='s',help="signs")
    group.add_argument('--master-sign', '-m',  dest='action', action='store_const', const='m',help="signs keys with your masterkey")
    group.add_argument('--verify',      '-v',  dest='action', action='store_const', const='v',help="verifies")
    group.add_argument('--hash',        '-H',  dest='action', action='store_const', const='h',help="hashes")
    group.add_argument('--list',        '-l',  dest='action', action='store_const', const='l',help="lists public keys")
    group.add_argument('--list-secret', '-L',  dest='action', action='store_const', const='L',help="Lists secret keys")
    group.add_argument('--export-key',  '-x',  dest='action', action='store_const', const='x',help="export public key")
    group.add_argument('--import-key',  '-I',  dest='action', action='store_const', const='i',help="import public key")
    group.add_argument('--check-sigs',  '-C',  dest='action', action='store_const', const='C',help="lists all known sigs on a public key")
    group.add_argument('--fcrypt',      '-e',  dest='action', action='store_const', const='e',help="encrypts a message using PFS to a peer")
    group.add_argument('--fdecrypt',    '-E',  dest='action', action='store_const', const='E',help="decrypts a message using PFS to a peer")
    group.add_argument(                 '-D1', dest='action', action='store_const', const='d1',help="initiates an ECDH key exchange")
    group.add_argument(                 '-D2', dest='action', action='store_const', const='d2',help="responds to an ECDH key request")
    group.add_argument(                 '-D3', dest='action', action='store_const', const='d3',help="finalizes an ECDH key exchange")
    group.add_argument('--dh-start',    '-Ds', dest='action', action='store_const', const='ds',help="initiates an ECDH key exchange")
    group.add_argument('--dh-end',      '-De', dest='action', action='store_const', const='de',help="finalizes an ECDH key exchange")
    group.add_argument('--rand-stream', '-R',  dest='action', action='store_const', const='R',help="generate arbitrary random stream")

    if PITCHFORK: parser.add_argument('--pitchfork',  '-P',  dest='PITCHFORK', action='store_const', const='P',help="arms PITCHFORK", default=False)
    parser.add_argument('--signature',  '-z', help="sets the pitchfork sig to verify")
    parser.add_argument('--recipient',  '-r', action='append', help="designates a recipient for public key encryption")
    parser.add_argument('--name',       '-n', help="sets the name for a new key")
    parser.add_argument('--max-recipients',   help="set the number of recipients to check when decrypting", default=20)
    parser.add_argument('--sender',           help="set the key of the sender")
    parser.add_argument('--basedir',    '-b', '--base-dir', help="set the base directory for all key storage needs", default=defaultbase)
    parser.add_argument('--self',       '-S', help="sets your own key")
    parser.add_argument('--key',        '-k', help="some password or secret")
    parser.add_argument('--dh-param',   '-DP',help="public parameter for ECDH key exchange")
    parser.add_argument('--dh-exp',     '-DE',help="secret exp for final step of a ECDH key exchange")
    parser.add_argument('--size',       '-Rs',help="size of random stream to generate")
    parser.add_argument('--dh-peers',   '-Dp',help="the number of peers participating in a ECDH key exchange")
    parser.add_argument('--infile',     '-i', help="file to operate on")
    parser.add_argument('--armor',      '-a', action='store_true', help="ascii armors the output")
    parser.add_argument('--outfile',    '-o', help="file to output to")
    opts=parser.parse_args()

    opts.basedir=os.path.expandvars( os.path.expanduser(opts.basedir))

    if os.path.exists(opts.basedir):
        mode = os.stat(opts.basedir).st_mode & 0777
        if mode not in [0700, 0600]:
            print >>sys.stderr, '[pbp] ABORT: unsafe permissions %s on basedir %s' % (oct(mode), opts.basedir)

    # Generate key
    if opts.action=='g':
        ensure_name_specified(opts)
        publickey.Identity(opts.name, create=True, basedir=opts.basedir)

    # list public keys
    elif opts.action=='l':
        if PITCHFORK and opts.PITCHFORK:
            pitchfork.init()
            res = pitchfork.listkeys(opts.name)
            if(res):
                keys, stats = res
                pitchfork.print_keys(keys)
                pitchfork.storage_stats(stats, keys)
            else:
                print 'none'
        else:
            for i in publickey.get_public_keys(opts.basedir):
                print ('valid' if i.valid > datetime.datetime.utcnow() > i.created
                       else 'INVALID'), i.keyid(), i.name

    # list secret keys
    elif opts.action=='L':
        for i in publickey.get_secret_keys(opts.basedir):
            print ('valid' if i.valid > datetime.datetime.utcnow() > i.created
                   else 'INVALID'), i.keyid(), i.name

    # encrypt
    elif opts.action=='c':
        if PITCHFORK and opts.PITCHFORK:
            ensure_recipient_specified(opts)
            pitchfork.init()
            res=pitchfork.encrypt(opts.recipient[0],
                                   infile=opts.infile,
                                   outfile=opts.outfile)
            if res:
                print >>sys.stderr, b85encode(res)
            return
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
        if PITCHFORK and opts.PITCHFORK:
            ensure_recipient_specified(opts)
            pitchfork.init()
            res=pitchfork.decrypt(opts.recipient[0],
                                  infile=opts.infile,
                                  outfile=opts.outfile)
        else:
            try:
                sender = decrypt_handler(infile=opts.infile,
                                         outfile=opts.outfile,
                                         self=opts.self,
                                         max_recipients=int(opts.max_recipients),
                                         peer=opts.sender,
                                         basedir=opts.basedir)
            except ValueError, e:
                print e
                sys.exit(1)
            else:
                if sender:
                    print >>sys.stderr, '[pbp] good message from', sender

    # sign
    elif opts.action=='s':
        if PITCHFORK and opts.PITCHFORK:
            ensure_recipient_specified(opts)
            pitchfork.init()
            res=pitchfork.sign(opts.recipient[0],
                               infile=opts.infile,
                               outfile=opts.outfile)
            if res:
                print >>sys.stderr, b85encode(res[0]), b85encode(res[1])
            return
        ensure_self_specified(opts)
        sign_handler(infile=opts.infile,
                     outfile=opts.outfile,
                     self=opts.self,
                     armor=opts.armor,
                     basedir=opts.basedir)

    # verify
    elif opts.action=='v':
        if PITCHFORK and opts.PITCHFORK:
            ensure_signature_specified(opts)
            ensure_recipient_specified(opts)
            pitchfork.init()
            res=pitchfork.verify(opts.signature,
                                 opts.recipient[0],
                                 infile=opts.infile,
                                 outfile=opts.outfile)
        else:
            res = verify_handler(infile=opts.infile,
                                 outfile=opts.outfile,
                                 basedir=opts.basedir)
        if res:
            print >>sys.stderr, "[pbp] good message from", res
        else:
            print >>sys.stderr, '[pbp] VERIFICATION FAILED'

    # key sign
    elif opts.action=='m':
        ensure_name_specified(opts)
        ensure_self_specified(opts)
        sig = keysign_handler(name=opts.name,
                              self=opts.self,
                              basedir=opts.basedir)
        if sig: print "[pbp] key signed in", sig
        else: print >>sys.stderr, '[pbp] SIGNATURE FAILED'

    # lists signatures owners on public keys
    elif opts.action=='C':
        ensure_name_specified(opts)
        sigs = keycheck_handler(name=opts.name,
                         basedir=opts.basedir)
        if sigs:
            print >>sys.stderr, '[pbp] good signatures on', opts.name, 'from', ', '.join(sigs)
        else: print >>sys.stderr, '[pbp] NO GOOD SIGS FOUND'

    # export public key
    elif opts.action=='x':
        ensure_self_specified(opts)
        k = export_handler(opts.self,
                           basedir=opts.basedir)
        print k
    # import public key
    elif opts.action=='i':
        n = import_handler(infile=opts.infile,
                           basedir=opts.basedir)
        if n:
            print '[pbp] Success: imported public keys for', n
        else:
            print '[pbp] IMPORT FAILED'

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
        if PITCHFORK and opts.PITCHFORK:
            ensure_recipient_specified(opts)
            pitchfork.init()
            params = pitchfork.start_ecdh(opts.recipient[0])
        else:
            params = dh1_handler()
        if params:
            print "[pbp] secret exponent", b85encode(params[0])
            print "[pbp] public component", b85encode(params[1])
            clearmem(params[0])
    # receive ECDH
    elif opts.action=='d2':
        ensure_dhparam_specified(opts)
        if PITCHFORK and opts.PITCHFORK:
            ensure_recipient_specified(opts)
            pitchfork.init()
            params = pitchfork.resp_ecdh(opts.dh_param, opts.recipient[0])
        else:
            params = dh2_handler(binascii.unhexlify(opts.dh_param))
        if params:
            print "[pbp] shared secret", b85encode(params[1])
            print "[pbp] public component", b85encode(params[0])
            clearmem(params[0])
            clearmem(params[1])
    # finish ECDH
    elif opts.action=='d3':
        ensure_dhparam_specified(opts)
        ensure_dhexp_specified(opts)
        if PITCHFORK and opts.PITCHFORK:
            pitchfork.init()
            sec = pitchfork.end_ecdh(opts.dh_param, opts.dh_exp)
        else:
            sec = dh3_handler(binascii.unhexlify(opts.dh_param), binascii.unhexlify(opts.dh_exp))
        if sec:
            print "[pbp] shared secret", b85encode(sec)
            clearmem(sec)
    # start MPECDH
    elif opts.action=='ds':
        ensure_self_specified(opts)
        ensure_dhpeers_specified(opts)
        ensure_name_specified(opts)
        sec = mpecdh_start_handler(opts.name, opts.dh_peers, opts.self, opts.infile, opts.outfile, opts.basedir)
        if sec:
            print >>sys.stderr, "[pbp] pushed shared secret, hash", b85encode(nacl.crypto_generichash(sec, outlen=6))
            clearmem(sec)
            sec = None

    # finish MPECDH
    elif opts.action=='de':
        ensure_self_specified(opts)
        ensure_name_specified(opts)
        sec = mpecdh_end_handler(opts.name, opts.self, opts.infile, opts.outfile, opts.basedir)
        if sec:
            print >>sys.stderr, "[pbp] pushed shared secret, hash", b85encode(nacl.crypto_generichash(sec, outlen=6))
            clearmem(sec)
            sec = None

    elif opts.action=='R':
        ensure_size_good(opts)
        if PITCHFORK and opts.PITCHFORK:
            pitchfork.init()
            pitchfork.rng(int(opts.size), opts.outfile)
        else:
            random_stream_handler(opts.outfile, opts.size)

    elif opts.action=='h':
        hsum = hash_handler(opts.infile, k=load_key(opts.key), outlen=int(opts.size or '16'))
        if hsum:
            print ' '.join(split_by_n(binascii.hexlify(hsum),4))

def load_key(key):
    # asserts that self is specified
    if not key:
        return None
    if os.path.exists(key):
        with open(key,'r') as fd:
            key = fd.read()
    return key

def ensure_self_specified(opts):
    # asserts that self is specified
    if not opts.self:
        die("Error: need to specify your own key using the --self param")

def ensure_name_specified(opts):
    # asserts that name is specified
    if not opts.name:
        die("Error: need to specify a key to operate on using the --name param")

def ensure_recipient_specified(opts):
    # asserts that recipient is specified
    if not opts.recipient:
        die("Error: need to specify a recipient to "
            "operate on using the --recipient param")

def ensure_signature_specified(opts):
    # asserts that recipient is specified
    if not opts.signature:
        die("Error: need to specify a signature to "
            "operate on using the --signature param")

def ensure_only_one_recipient(opts):
    # asserts that only one recipient is specified
    if len(opts.recipient) > 1:
        die("Error: you can only PFS decrypt from one recipient.")

def ensure_dhexp_specified(opts):
    # asserts that dhexp is specified
    if not opts.dh_exp:
        die("Error: need to specify number of peers in the ECDH key exchange using the -DE param")

def ensure_dhpeers_specified(opts):
    # asserts that dhpeers is specified
    if not opts.dh_peers:
        die("Error: need to specify number of peers in the ECDH key exchange using the -Dp param")

def ensure_dhparam_specified(opts):
    # asserts that dhpeers is specified
    if not opts.dh_param:
        die("Error: need to specify number of peers in the ECDH key exchange using the -DP param")

def ensure_size_good(opts):
    # asserts that size is specified, and expands any postfixes KMGT
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
    # complains and dies
    print >>sys.stderr, msg
    sys.exit(1)

if __name__ == '__main__':
    lockmem()
    main()
