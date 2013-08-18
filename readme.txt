# this is a automatic install script besides
# use:
# wget -O - https://raw.github.com/stef/pbp/master/readme.txt | sh -
# to install pbp automatically
# you possibly need to run (or an equivalent command)
# sudo apt-get install git python-virtualenv gcc
# to satisfy all basic dependencies

# unfortunately all this is neccessary as nacl needs to be compiled as
# a dependency.

# (c) 2013, Stefan Marsiske <s@ctrlc.hu>, AGPLv3.0+
# v0.1 - experimental
# TODO implement buffering for file ops
# TODO implement ascii armoring
# TODO implement --outfile

set -x
git clone https://github.com/stef/pbp.git
cd pbp

virtualenv env
source env/bin/activate

git clone git://github.com/seanlynch/pynacl.git
cd pynacl/nacl-20110221
set +x
echo "the following compilation can take 30m on 3-4 year old hw"
echo "please be patient"
set -x
./do

cd ..
python ./setup.py install
cd ..
rm -rf pynacl

pip install -r deps.txt

# check out test.sh for examples how to use pbp.py
./pbp.py -h
