#!/usr/bin/ksh

rm -rf ./test-pbp
echo create some keys
echo create alice
./pbp.py -g -n alice -b ./test-pbp || exit
echo create bob
./pbp.py -g -n bob -b ./test-pbp || exit
echo create carol
./pbp.py -g -n carol -b ./test-pbp || exit

# test msg
cat >./test-pbp/howdy.txt <<EOF
hello world
EOF

echo public key crypto test
./pbp.py -c -S alice -r bob -i ./test-pbp/howdy.txt -b ./test-pbp || exit
echo decrypt
./pbp.py -d -S bob -i ./test-pbp/howdy.txt.pbp -b ./test-pbp || exit

echo secret key crypto test
./pbp.py -c -i ./test-pbp/howdy.txt || exit
echo decrypt
./pbp.py -d -i ./test-pbp/howdy.txt.pbp || exit

echo public key signature test
./pbp.py -s -S alice -i ./test-pbp/howdy.txt -b ./test-pbp || exit
echo verify
./pbp.py -v -i ./test-pbp/howdy.txt.sig -b ./test-pbp || exit

echo some key signing tests
./pbp.py -m -S alice -n bob -b ./test-pbp || exit
./pbp.py -m -S alice -n carol -b ./test-pbp || exit
./pbp.py -m -S bob -n carol -b ./test-pbp || exit

echo check sigs on carols key
./pbp.py -C -n carol -b ./test-pbp || exit
./pbp.py -C -n bob -b ./test-pbp || exit

echo test PFS mode
rm ./test-pbp/sk/.alice/bob ./test-pbp/sk/.bob/alice /tmp/[24]bob* /tmp/[24]alice*
./pbp.py -e -S alice -r bob -b ./test-pbp -i ./test-pbp/howdy.txt -o /tmp/2bob || exit
./pbp.py -E -S bob -r alice -b ./test-pbp/ -i /tmp/2bob || exit
./pbp.py -e -S bob -r alice -b ./test-pbp/ -i ./test-pbp/howdy.txt -o /tmp/2alice || exit
./pbp.py -E -S alice -r bob -b ./test-pbp/ -i /tmp/2alice || exit
./pbp.py -e -S alice -r bob -b ./test-pbp -i ./test-pbp/howdy.txt -o /tmp/2bob || exit
./pbp.py -E -S bob -r alice -b ./test-pbp/ -i /tmp/2bob || exit
./pbp.py -e -S bob -r alice -b ./test-pbp/ -i ./test-pbp/howdy.txt -o /tmp/2alice || exit
./pbp.py -E -S alice -r bob -b ./test-pbp/ -i /tmp/2alice -o /tmp/4alice || exit
echo test some repeated msgs
./pbp.py -e -S alice -r bob -b ./test-pbp -i ./test-pbp/howdy.txt -o /tmp/2bob || exit
./pbp.py -e -S alice -r bob -b ./test-pbp -i ./test-pbp/howdy.txt -o /tmp/2bob-2 || exit
./pbp.py -E -S bob -r alice -b ./test-pbp/ -i /tmp/2bob || exit
./pbp.py -E -S bob -r alice -b ./test-pbp/ -i /tmp/2bob-2 || exit
./pbp.py -e -S bob -r alice -b ./test-pbp/ -i ./test-pbp/howdy.txt -o /tmp/2alice || exit
./pbp.py -E -S alice -r bob -b ./test-pbp/ -i /tmp/2alice -o /tmp/4alice || exit

echo testing random number streaming
./pbp.py -R -Rs 99999999 | pv -ftrab >/dev/null

