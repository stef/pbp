#!/usr/bin/ksh

rm -rf ./test-pbp
# create some keys
./pbp.py -g -n alice -b ./test-pbp || exit
./pbp.py -g -n bob -b ./test-pbp || exit
./pbp.py -g -n carol -b ./test-pbp || exit

# test msg
cat >./test-pbp/howdy.txt <<EOF
hello world
EOF

# public key crypto test
./pbp.py -c -S alice -r bob -i ./test-pbp/howdy.txt -b ./test-pbp || exit
# decrypt
./pbp.py -d -S bob -i ./test-pbp/howdy.txt.pbp -b ./test-pbp || exit

# secret key crypto test
./pbp.py -c -i ./test-pbp/howdy.txt || exit
# decrypt
./pbp.py -d -i ./test-pbp/howdy.txt.pbp || exit

# public key signature test
./pbp.py -s -S alice -i ./test-pbp/howdy.txt -b ./test-pbp || exit
# verify
./pbp.py -v -i ./test-pbp/howdy.txt.sig -b ./test-pbp || exit

# some key signing tests
./pbp.py -m -S alice -n bob -b ./test-pbp || exit
./pbp.py -m -S alice -n carol -b ./test-pbp || exit
./pbp.py -m -S bob -n carol -b ./test-pbp || exit

# check sigs on carols key
./pbp.py -C -n carol -b ./test-pbp || exit
./pbp.py -C -n bob -b ./test-pbp || exit

# test PFS mode
rm ./test-pbp/sk/.alice/bob ./test-pbp/sk/.bob/alice /tmp/[24]bob* /tmp/[24]alice*
./pbp.py -e -S alice -r bob -b ./test-pbp -i ./test-pbp/howdy.txt -o /tmp/2bob || exit
./pbp.py -E -S bob -r alice -b ./test-pbp/ -i /tmp/2bob || exit
./pbp.py -e -S bob -r alice -b ./test-pbp/ -i ./test-pbp/howdy.txt -o /tmp/2alice || exit
./pbp.py -E -S alice -r bob -b ./test-pbp/ -i /tmp/2alice || exit
./pbp.py -e -S alice -r bob -b ./test-pbp -i ./test-pbp/howdy.txt -o /tmp/2bob || exit
./pbp.py -E -S bob -r alice -b ./test-pbp/ -i /tmp/2bob || exit
./pbp.py -e -S bob -r alice -b ./test-pbp/ -i ./test-pbp/howdy.txt -o /tmp/2alice || exit
./pbp.py -E -S alice -r bob -b ./test-pbp/ -i /tmp/2alice -o /tmp/4alice || exit
# test some repeated msgs
./pbp.py -e -S alice -r bob -b ./test-pbp -i ./test-pbp/howdy.txt -o /tmp/2bob || exit
./pbp.py -e -S alice -r bob -b ./test-pbp -i ./test-pbp/howdy.txt -o /tmp/2bob-2 || exit
./pbp.py -E -S bob -r alice -b ./test-pbp/ -i /tmp/2bob || exit
./pbp.py -E -S bob -r alice -b ./test-pbp/ -i /tmp/2bob-2 || exit
./pbp.py -e -S bob -r alice -b ./test-pbp/ -i ./test-pbp/howdy.txt -o /tmp/2alice || exit
./pbp.py -E -S alice -r bob -b ./test-pbp/ -i /tmp/2alice -o /tmp/4alice || exit
