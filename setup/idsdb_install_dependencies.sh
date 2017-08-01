#!/bin/bash

#./idsdb_install_dependencies.sh
# installs all dependencies for IDSDB

# enable below if needed for troubleshooting
#set -e 

sudo apt-get update && sudo apt-get upgrade

sudo apt-get install lua-apr lua-apr-dev build-essential libapr1 \
libapr1-dev libnspr4-dev libnss3-dev libwww-perl libcrypt-ssleay-perl python-dev \
python-scapy python-yaml bison libpcre3-dev bison flex ruby-pcaprub libdumbnet-dev \
autotools-dev libnet1-dev libpcap-dev libyaml-dev libnetfilter-queue-dev \
libprelude-dev zlib1g-dev libcap-ng-dev libmagic-dev \
python-mysqldb luarocks cmake libjansson-dev \
python-yaml python-mysqldb python-simplejson mysql-server \
libswitch-perl autoconf automake libtool git-core liblua5.1-0 liblua5.1-0-dev libapr1 \
libapr1-dev libaprutil1 libaprutil1-dev libaprutil1-dbd-sqlite3 libapreq2-3 \
libapreq2-dev luarocks libzzip-dev liblua5.1-bitop-dev liblua5.1-bitop 

sudo luarocks install struct
sudo luarocks install lua-apr

rm -rf engine-sources/misc/ltn12ce
git clone https://github.com/mkottman/ltn12ce engine-sources/misc/ltn12ce
cd engine-sources/misc/ltn12ce
mkdir build
cd build
cmake .. -DBUILD_ZLIB=Off -DLUA_LIBRARY=/usr/lib/x86_64-linux-gnu/liblua5.1.so -DLUA_INCLUDE_DIR=/usr/include/lua5.1/
make
sudo make install
cd ../../
sudo ln -s /usr/local/lib/lua/ltn12ce /usr/local/lib/lua/5.1/ltn12ce
cd ../../


rm -rf engine-sources/misc/luazip-1.2.4-1/
tar -xzvf engine-sources/misc/luazip-1.2.4-1.tar.gz -C engine-sources/misc
rm engine-sources/misc/luazip-1.2.4-1/luazip/src/luazip.c
cp -f engine-sources/misc/luazip.c engine-sources/misc/luazip-1.2.4-1/luazip/src/
cd engine-sources/misc/luazip-1.2.4-1/luazip
sudo luarocks make luazip-1.2.4-1.rockspec
cd ../../../../

rm -rf engine-sources/misc/libdnet-1.11/ 
tar -xzvf engine-sources/misc/libdnet-1.11.tar.gz -C engine-sources/misc
cd engine-sources/misc/libdnet-1.11
./configure "CFLAGS=-fPIC -g -O2" --prefix=/opt/libdnet111/ 
make && sudo make install
cd ../../../

rm -rf engine-sources/misc/lua-zlib/ 
mkdir engine-sources/misc/lua-zlib
cd engine-sources/misc/lua-zlib
git clone https://github.com/brimworks/lua-zlib.git
cmake lua-zlib
cd lua-zlib
sudo luarocks make
cd ../../../../

rm -rf /opt/et-luajit-scripts
sudo git clone https://github.com/EmergingThreats/et-luajit-scripts /opt/et-luajit-scripts
