#!/usr/bin/ksh

rm -rf test-pbp
# create some keys
./pbp.py -g -n alice -b test-pbp
./pbp.py -g -n bob -b test-pbp
./pbp.py -g -n carol -b test-pbp

# test msg
cat >test-pbp/howdy.txt <<EOF
hello world
EOF

# public key crypto test
./pbp.py -c -S alice -r bob -i test-pbp/howdy.txt -b test-pbp
# decrypt
./pbp.py -d -S bob -i test-pbp/howdy.txt.pbp -b test-pbp

# secret key crypto test
./pbp.py -c -i test-pbp/howdy.txt
# decrypt
./pbp.py -d -i test-pbp/howdy.txt.pbp

# public key signature test
./pbp.py -s -S alice -i test-pbp/howdy.txt -b test-pbp
# verify
./pbp.py -v -i test-pbp/howdy.txt.sig -b test-pbp

# some key signing tests
./pbp.py -m -S alice -n bob -b test-pbp
./pbp.py -m -S alice -n carol -b test-pbp
./pbp.py -m -S bob -n carol -b test-pbp

# check sigs on carols key
./pbp.py -C -n carol -b test-pbp
./pbp.py -C -n bob -b test-pbp

# test PFS mode
rm test-pbp/sk/.alice/bob test-pbp/sk/.bob/alice
./pbp.py -e -S alice -r bob -b test-pbp -i test-pbp/howdy.txt -o /tmp/a
./pbp.py -E -S bob -r alice -b test-pbp/ -i /tmp/a -o /tmp/b
./pbp.py -e -S bob -r alice -b test-pbp/ -i /tmp/b -o /tmp/c
./pbp.py -E -S alice -r bob -b test-pbp/ -i /tmp/c -o /tmp/d
./pbp.py -e -S alice -r bob -b test-pbp/ -i /tmp/d -o /tmp/e
./pbp.py -E -S bob -r alice -b test-pbp/ -i /tmp/e -o /tmp/f
./pbp.py -e -S bob -r alice -b test-pbp/ -i /tmp/f -o /tmp/g
./pbp.py -E -S alice -r bob -b test-pbp/ -i /tmp/g -o /tmp/h
./pbp.py -e -S alice -r bob -b test-pbp/ -i /tmp/h -o /tmp/i
./pbp.py -E -S bob -r alice -b test-pbp/ -i /tmp/i -o /tmp/j

echo "difference between howdy.txt and /tmp/j"
diff /tmp/j test-pbp/howdy.txt && echo None
rm test-pbp/sk/.alice/bob test-pbp/sk/.bob/alice /tmp/[abcdefghij]
