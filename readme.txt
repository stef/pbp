pbp

(c) 2013, Stefan Marsiske <s@ctrlc.hu>, AGPLv3.0+
v0.4.99 - experimental

PBP is a simple python wrapper around libsodium, to provide basic
functionality resembling PGP. It uses scrypt for a KDF and a much
simpler packet format, that is much harder to fingerprint, and
provides a forward secrecy mode.

Installation

The install.txt is also a automatic install script use:

   wget -O - https://raw.github.com/stef/pbp/master/install.txt | sh -

you possibly need to run (or an equivalent command) sudo apt-get
install git python-virtualenv gcc python-dev to satisfy all basic
dependencies

Design goals:

 1. use modern crypo based on NaCl
 2. provide similar functionality to PGP
 3. be extensible
 4. difficult to identify based on fingerprinting

Usage:

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
