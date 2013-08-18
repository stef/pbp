# this is a automatic install script besides
# use:
# wget -O - https://raw.github.com/stef/pbp/master/readme.txt | sh -
# to install pbp automatically

# unfortunately all this is neccessary as nacl needs to be compiled as
# a dependency.

# (c) 2013, Stefan Marsiske <s@ctrlc.hu>, AGPLv3.0+
# v0.1 - experimental
# TODO implement buffering for file ops
# TODO implement ascii armoring
# TODO implement --outfile

set -x
wget http://hyperelliptic.org/nacl/nacl-20110221.tar.bz2 || exit 1
bunzip2 < nacl-20110221.tar.bz2 | tar -xf -
cd nacl-20110221
export NACL_DIR="$PWD"
sed -i "s/$/ -fPIC/" okcompilers/c*
set +x
echo "the following compilation can take 30m on 3-4 year old hw"
echo "please be patient"
set -x
./do

cd ..
git clone https://github.com/stef/pbp.git
cd pbp

virtualenv env
pip install -r deps.txt

# check out test.sh for examples how to use pbp.py
./pbp.py -h
