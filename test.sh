#!/usr/bin/ksh

rm -rf test.pbp
# create some keys
./pep.py -g -n alice -b test.pbp
./pep.py -g -n bob -b test.pbp
./pep.py -g -n carol -b test.pbp

# test msg
cat >test.pbp/howdy.txt <<EOF
hello world
EOF

# public key crypto test
./pep.py -c -S alice -r bob -i test.pbp/howdy.txt -b test.pbp
# decrypt
./pep.py -d -S bob -i test.pbp/howdy.txt.pbp -b test.pbp

# secret key crypto test
./pep.py -c -i test.pbp/howdy.txt
# decrypt
./pep.py -d -i test.pbp/howdy.txt.pbp

# public key signature test
./pep.py -s -S alice -i test.pbp/howdy.txt -b test.pbp
# verify
./pep.py -v -i test.pbp/howdy.txt.sig -b test.pbp
