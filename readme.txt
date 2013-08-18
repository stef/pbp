# this is a automatic install script besides
# use 
# wget -O - https://raw.github.com/stef/pbp/master/readme.txt | sh -
# to install pbp automatically

set -x
wget http://hyperelliptic.org/nacl/nacl-20110221.tar.bz2 || exit 1
bunzip2 < nacl-20110221.tar.bz2 | tar -xf -
cd nacl-20110221
export NACL_DIR="$PWD"
sed -i "s/$/ -fPIC/" okcompilers/c*
echo "the following compilation can take 30m on 3-4 year old hw"
echo "please be patient"
./do

cd ..
git clone https://github.com/stef/pbp.git
cd pbp

virtualenv env
pip install -r deps.txt
