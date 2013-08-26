pbp

v0.4.99 - experimental

PBP is a simple python wrapper around libsodium, to provide basic
functionality resembling PGP. It uses scrypt for a KDF and a much
simpler packet format, which should be much harder to fingerprint and
also provides a forward secrecy mode.

Installation

The install.txt is also a automatic install script use:

   wget -O - https://raw.github.com/stef/pbp/master/install.txt | sh -

you possibly need to run (or an equivalent command) sudo apt-get
install git python-virtualenv gcc python-dev to satisfy all basic
dependencies

TODO

setup.py

Design goals:

 1. use modern crypto
 2. provide similar functionality to PGP
 3. be extensible
 4. difficult to identify based on fingerprinting
 5. provide extensive testing
 6. strive for security

Crypto

Cryptographic primitives are based on the NaCl library from
http://nacl.cr.yp.to. The KDF used is scrypt.

PGP-like

Provides basic public key encrypt/decrypt, sign/verify and secret key
encrypt/decrypt modes, as well as the ability to sign, verify, list,
generate, export and import keys. 

Extensibility

using pbp and the underlying pysodium[1] library it's easy to extend pbp.
Two examples are the experimental forward secrecy mode (see
description in docs/chaining-dh.txt) and the support for ECDH key
exchanges from the command-line.

[1] https://github.com/stef/pysodium also available on
    https://pypi.python.org/pypi/pysodium

Fingerprinting

pbp tries to avoid to store any sensitive plaintext info, the
encrypted files all should look like random noise. for a description
of the packet formats see docs/fileformats.txt.

Testing

All py files come with their internal tests, unit tests are in
tests.py, and commandline functionality is tested in test.sh.

Security

pbp locks the process memory, so it cannot be swapped to disk. Also
pbp tries to overwrite sensitive key material after usage in memory,
so it can only be briefly dumped.

Usage

Generate a key

   pbp.py -g -n alice

sending howdy.txt using public key encryption from alice to bob

   pbp.py -c -S alice -r bob -i howdy.txt

decrypt an encrypted flie using public key crypto

   pbp.py -d -S bob -i howdy.txt.pbp

sending howdi.txt using secret key encryption

   pbp.py -c -i howdy.txt

decrypt an encrypted flie using secret key crypto

   pbp.py -d -i howdy.txt.pbp

sign howdy.txt

   pbp.py -s -S alice -i /howdy.txt

verify howdy.txt

   pbp.py -v -i howdy.txt.sig

sign bobs key

   pbp.py -m -S alice -n bob

check sigs on carols key

   pbp.py -C -n carol

alice encrypts howdy.txt to bob using experimental forward secret mode

   pbp.py -e -S alice -r bob -i howdy.txt -o ./secret-message

bob decrypts howdy.txt from alice using experimental forward secret mode

   pbp.py -E -S bob -r alice -i ./secret-message

initiate ECDH key exchange

   pbp.py -D1

respond to ECDH key exchange

   pbp.py -D2 -Dp 'public component from D1'

finish ECDH key exchange

  pbp.py -D3 -Dp 'public component from D2' -De 'secret exponent from D1'


(c) 2013, stf <s@ctrlc.hu>, dnet vsza@vsza.hu, AGPLv3.0+
