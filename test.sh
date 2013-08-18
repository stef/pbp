#!/usr/bin/ksh

rm -rf test.pbp
# create some keys
./pbp.py -g -n alice -b test.pbp
./pbp.py -g -n bob -b test.pbp
./pbp.py -g -n carol -b test.pbp

# test msg
cat >test.pbp/howdy.txt <<EOF
hello world
EOF

# public key crypto test
./pbp.py -c -S alice -r bob -i test.pbp/howdy.txt -b test.pbp
# decrypt
./pbp.py -d -S bob -i test.pbp/howdy.txt.pbp -b test.pbp

# secret key crypto test
./pbp.py -c -i test.pbp/howdy.txt
# decrypt
./pbp.py -d -i test.pbp/howdy.txt.pbp

# public key signature test
./pbp.py -s -S alice -i test.pbp/howdy.txt -b test.pbp
# verify
./pbp.py -v -i test.pbp/howdy.txt.sig -b test.pbp

# some key signing tests
./pbp.py -m -S alice -n bob -b test.pbp
./pbp.py -m -S alice -n carol -b test.pbp
./pbp.py -m -S bob -n carol -b test.pbp

# check sigs on carols key
./pbp.py -C -n carol -b test.pbp
./pbp.py -C -n bob -b test.pbp
