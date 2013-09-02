#!/usr/bin/ksh

rm -rf ./test-pbp
echo create some keys
echo create alice
pbp -g -n alice -b ./test-pbp || exit
echo create bob
pbp -g -n bob -b ./test-pbp || exit
echo create carol
pbp -g -n carol -b ./test-pbp || exit

# test msg
cat >./test-pbp/howdy.txt <<EOF
hello world
EOF

echo public key crypto test
pbp -c -S alice -r bob -i ./test-pbp/howdy.txt -b ./test-pbp || exit
echo decrypt
pbp -d -S bob -i ./test-pbp/howdy.txt.pbp -b ./test-pbp || exit

echo secret key crypto test
pbp -c -i ./test-pbp/howdy.txt || exit
echo decrypt
pbp -d -i ./test-pbp/howdy.txt.pbp || exit

echo public key signature test
pbp -s -S alice -i ./test-pbp/howdy.txt -b ./test-pbp || exit
echo verify
pbp -v -i ./test-pbp/howdy.txt.sig -b ./test-pbp || exit

echo some key signing tests
pbp -m -S alice -n bob -b ./test-pbp || exit
pbp -m -S alice -n carol -b ./test-pbp || exit
pbp -m -S bob -n carol -b ./test-pbp || exit

echo check sigs on carols key
pbp -C -n carol -b ./test-pbp || exit
pbp -C -n bob -b ./test-pbp || exit

echo test PFS mode
rm ./test-pbp/sk/.alice/bob ./test-pbp/sk/.bob/alice /tmp/[24]bob* /tmp/[24]alice*
pbp -e -S alice -r bob -b ./test-pbp -i ./test-pbp/howdy.txt -o /tmp/2bob || exit
pbp -E -S bob -r alice -b ./test-pbp/ -i /tmp/2bob || exit
pbp -e -S bob -r alice -b ./test-pbp/ -i ./test-pbp/howdy.txt -o /tmp/2alice || exit
pbp -E -S alice -r bob -b ./test-pbp/ -i /tmp/2alice || exit
pbp -e -S alice -r bob -b ./test-pbp -i ./test-pbp/howdy.txt -o /tmp/2bob || exit
pbp -E -S bob -r alice -b ./test-pbp/ -i /tmp/2bob || exit
pbp -e -S bob -r alice -b ./test-pbp/ -i ./test-pbp/howdy.txt -o /tmp/2alice || exit
pbp -E -S alice -r bob -b ./test-pbp/ -i /tmp/2alice -o /tmp/4alice || exit
echo test some repeated msgs
pbp -e -S alice -r bob -b ./test-pbp -i ./test-pbp/howdy.txt -o /tmp/2bob || exit
pbp -e -S alice -r bob -b ./test-pbp -i ./test-pbp/howdy.txt -o /tmp/2bob-2 || exit
pbp -E -S bob -r alice -b ./test-pbp/ -i /tmp/2bob || exit
pbp -E -S bob -r alice -b ./test-pbp/ -i /tmp/2bob-2 || exit
pbp -e -S bob -r alice -b ./test-pbp/ -i ./test-pbp/howdy.txt -o /tmp/2alice || exit
pbp -E -S alice -r bob -b ./test-pbp/ -i /tmp/2alice -o /tmp/4alice || exit

echo testing random number streaming
pbp -R -Rs 99999999 | pv -ftrab >/dev/null

