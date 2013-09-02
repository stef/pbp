#!/usr/bin/env python2
import argparse, os, sys, datetime
from utils import b85encode, lockmem
from SecureString import clearmem
import publickey
from pbp import defaultbase, encrypt_handler, decrypt_handler, sign_handler
from pbp import verify_handler, keysign_handler, keycheck_handler, export_handler
from pbp import import_handler, chaining_encrypt_handler, chaining_decrypt_handler
from pbp import dh1_handler, dh2_handler, dh3_handler, random_stream_handler
from pbp import _prev_passphrase

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
        res = verify_handler(infile=opts.infile,
                             outfile=opts.outfile,
                             basedir=opts.basedir)
        if res:
            print >>sys.stderr, "good message from", res
        else:
            print >>sys.stderr, 'verification failed'

    # key sign
    elif opts.action=='m':
        ensure_name_specified(opts)
        ensure_self_specified(opts)
        sig = keysign_handler(name=opts.name,
                              self=opts.self,
                              basedir=opts.basedir)
        if sig: print "key signed in", sig
        else: print >>sys.stderr, 'signature failed'

    # lists signatures owners on public keys
    elif opts.action=='C':
        ensure_name_specified(opts)
        sigs = keycheck_handler(name=opts.name,
                         basedir=opts.basedir)
        if sigs:
            print >>sys.stderr, 'good signatures on', opts.name, 'from', ', '.join(sigs)
        else: print >>sys.stderr, 'no good sigs found'

    # export public key
    elif opts.action=='x':
        ensure_self_specified(opts)
        k = export_handler(opts.self,
                           basedir=opts.basedir)
        print k
    # import public key
    elif opts.action=='X':
        n = import_handler(infile=opts.infile,
                           basedir=opts.basedir)
        if n:
            print 'Success: imported public keys for', n
        else:
            print 'import failed'

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
        params = dh1_handler()
        if params:
            print "secret exponent", b85encode(params[0])
            print "public component", b85encode(params[1])
            clearmem(params[0])
    # receive ECDH
    elif opts.action=='d2':
        ensure_dhparam_specified(opts)
        params = dh2_handler(opts.dh_param)
        if params:
            print "public component", b85encode(params[0])
            print "shared secret", b85encode(params[1])
            clearmem(params[0])
            clearmem(params[1])
    # finish ECDH
    elif opts.action=='d3':
        ensure_dhparam_specified(opts)
        ensure_dhexp_specified(opts)
        sec = dh3_handler(opts.dh_param, opts.dh_exp)
        if sec:
            print "shared secret", b85encode(sec)
            clearmem(sec)

    elif opts.action=='R':
        ensure_size_good(opts)
        random_stream_handler(opts.outfile, opts.size)

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

def ensure_only_one_recipient(opts):
    # asserts that only one recipient is specified
    if len(opts.recipient) > 1:
        die("Error: you can only PFS decrypt from one recipient.")

def ensure_dhparam_specified(opts):
    # asserts that dhparam is specified
    if not opts.dh_param:
        die("Error: need to specify the ECDH public parameter using the -Dp param")

def ensure_dhexp_specified(opts):
    # asserts that dhexp is specified
    if not opts.dh_exp:
        die("Error: need to specify your secret ECDH exponent using the -De param")

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
    clearmem(_prev_passphrase)
