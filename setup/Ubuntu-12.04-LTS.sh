#/bin/sh
sudo mkdir -p /opt/snort2841/{bin,lib,include/linux,sbin,etc/etpro,etc/etopen,/etc/test,var/log}
sudo mkdir -p /opt/snort2861/{bin,lib,include/linux,sbin,etc/etpro,etc/etopen,/etc/test,var/log}
sudo mkdir -p /opt/snort2904/{bin,lib,include/linux,sbin,etc/etpro,etc/etopen,/etc/test,var/log}
sudo mkdir -p /opt/snort2905/{bin,lib,include/linux,sbin,etc/etpro,etc/etopen,/etc/test,var/log}
sudo mkdir -p /opt/snort2922/{bin,lib,include/linux,sbin,etc/etpro,etc/etopen,/etc/test,var/log}
sudo mkdir -p /opt/snort2923/{bin,lib,include/linux,sbin,etc/etpro,etc/etopen,/etc/test,var/log}
sudo mkdir -p /opt/snort293/{bin,lib,include/linux,sbin,etc/etpro,etc/etopen,/etc/test,var/log}
sudo mkdir -p /opt/snort2931/{bin,lib,include/linux,sbin,etc/etpro,etc/etopen,/etc/test,var/log}
sudo mkdir -p /opt/snort294/{bin,lib,include/linux,sbin,etc/etpro,etc/etopen,/etc/test,var/log}
sudo mkdir -p /opt/suricata121/{bin,lib,include/linux,sbin,etc/etpro,etc/etopen,/etc/test,var/log}
sudo mkdir -p /opt/suricata13/{bin,lib,include/linux,sbin,etc/etpro,etc/etopen,/etc/test,var/log}
sudo mkdir -p /opt/suricata13JIT/{bin,lib,include/linux,sbin,etc/etpro,etc/etopen,/etc/test,var/log}
sudo mkdir -p /opt/suricata131/{bin,lib,include/linux,sbin,etc/etpro,etc/etopen,/etc/test,var/log}
sudo mkdir -p /opt/suricata131JIT/{bin,lib,include/linux,sbin,etc/etpro,etc/etopen,/etc/test,var/log}
sudo mkdir -p /opt/suricata135/{bin,lib,include/linux,sbin,etc/etpro,etc/etopen,/etc/test,var/log}
sudo mkdir -p /opt/suricata135JIT/{bin,lib,include/linux,sbin,etc/etpro,etc/etopen,/etc/test,var/log}
sudo mkdir -p /opt/suricata14/{bin,lib,include/linux,sbin,etc/etpro,etc/etopen,/etc/test,var/log}
sudo mkdir -p /opt/suricata14JIT/{bin,lib,include/linux,sbin,etc/etpro,etc/etopen,/etc/test,var/log}
NUM_CORES=`grep processor /proc/cpuinfo | sort -u | wc -l`

sudo apt-get install build-essential libnspr4-dev libnss3-dev libwww-Perl libcrypt-ssleay-perl python-dev python-scapy python-yaml bison libpcre3-dev bison flex libpcap-ruby libdumbnet-dev autotools-dev libnet1-dev libpcap-dev libyaml-dev libnetfilter-queue-dev libprelude-dev zlib1g-dev  libz-dev libcap-ng-dev libmagic-dev python-mysqldb liblua5.1-zip-dev luarocks cmake

tar -xzvf snort_2.8.4.1.orig.tar.gz
cd snort-2.8.4.1
./configure --enable-perfprofiling --prefix=/opt/snort2841/ && make -j && sudo make install
sudo cp etc/* /opt/snort2841/etc/
cd ..

tar -xzvf snort-2.8.6.1.tar.gz
cd snort-2.8.6.1
./configure --enable-perfprofiling --prefix=/opt/snort2861/ && make -j && sudo make install
sudo cp etc/* /opt/snort2861/etc/
cd ..

tar -xzvf pcre-8.31.tar.gz
cd pcre-8.31
./configure --prefix=/opt/pcre-8.31/ --enable-jit --enable-utf8 --enable-unicode-properties
make -j && sudo make install
cd ..

tar -xzvf suricata-1.2.1.tar.gz
cd suricata-1.2.1
./configure --enable-profiling --prefix=/opt/suricata121/ --with-libnss-includes=/usr/include/nss --with-libnss-libs=/usr/lib/nss --with-libnspr-includes=/usr/include/nspr --with-libnspr-libraries=/usr/lib/nspr && make -j && sudo make install
sudo cp suricata.yaml /opt/suricata121/etc/
sudo cp ../reference.config /opt/suricata121/etc/
sudo cp ../classification.config /opt/suricata121/etc/
cd ..

tar -xzvf suricata-1.3.tar.gz
cd suricata-1.3
./configure --enable-profiling --prefix=/opt/suricata13/ --with-libnss-includes=/usr/include/nss --with-libnss-libs=/usr/lib/nss --with-libnspr-includes=/usr/include/nspr --with-libnspr-libraries=/usr/lib/nspr && make -j && sudo make install
sudo cp suricata.yaml /opt/suricata13/etc/
sudo cp ../reference.config /opt/suricata13/etc/
sudo cp ../classification.config /opt/suricata13/etc/
make distclean
./configure LD_RUN_PATH="/opt/pcre-8.31/lib:/usr/lib:/usr/local/lib" --enable-pcre-jit --with-libpcre-libraries=/opt/pcre-8.31/lib/ --with-libpcre-includes=/opt/pcre-8.31/include/ --enable-profiling --prefix=/opt/suricata13JIT/ --with-libnss-includes=/usr/include/nss --with-libnss-libs=/usr/lib/nss --with-libnspr-includes=/usr/include/nspr --with-libnspr-libraries=/usr/lib/nspr && make -j && sudo make install
sudo cp suricata.yaml /opt/suricata13JIT/etc/
sudo cp ../reference.config /opt/suricata13JIT/etc/
sudo cp ../classification.config /opt/suricata13JIT/etc/
cd ..

tar -xzvf suricata-1.3.1.tar.gz
cd suricata-1.3.1
./configure --enable-profiling --prefix=/opt/suricata131/ --with-libnss-includes=/usr/include/nss --with-libnss-libs=/usr/lib/nss --with-libnspr-includes=/usr/include/nspr --with-libnspr-libraries=/usr/lib/nspr && make -j && sudo make install
sudo cp suricata.yaml /opt/suricata131/etc/
sudo cp ../reference.config /opt/suricata131/etc/
sudo cp ../classification.config /opt/suricata131/etc/
make distclean
./configure LD_RUN_PATH="/opt/pcre-8.31/lib:/usr/lib:/usr/local/lib" --enable-pcre-jit --with-libpcre-libraries=/opt/pcre-8.31/lib/ --with-libpcre-includes=/opt/pcre-8.31/include/ --enable-profiling --prefix=/opt/suricata131JIT/ --with-libnss-includes=/usr/include/nss --with-libnss-libs=/usr/lib/nss --with-libnspr-includes=/usr/include/nspr --with-libnspr-libraries=/usr/lib/nspr && make -j && sudo make install
sudo cp suricata.yaml /opt/suricata131JIT/etc/
sudo cp ../reference.config /opt/suricata131JIT/etc/
sudo cp ../classification.config /opt/suricata131JIT/etc/
cd ..

tar -xzvf LuaJIT-2.0.0.tar.gz
cd LuaJIT-2.0.0
sed -i -e "s/\/usr\/local/\/opt\/luajit20/g" Makefile
make -j   
sudo make install
cd ..

sudo ln -s /usr/lib/x86_64-linux-gnu/lua/5.1/zip.so /opt/luajit20/lib/lua/5.1/zip.so
sudo luarocks install struct
mkdir lua-zlib
cd lua-zlib
git clone https://github.com/brimworks/lua-zlib.git
cmake lua-zlib
cd lua-zlib 
make
sudo make install
cd ../..

tar -xzvf suricata-1.3.5.tar.gz
cd suricata-1.3.5
./configure --enable-profiling --prefix=/opt/suricata135/ --with-libnss-includes=/usr/include/nss --with-libnss-libs=/usr/lib/nss --with-libnspr-includes=/usr/include/nspr --with-libnspr-libraries=/usr/lib/nspr && make -j && sudo make install
sudo cp suricata.yaml /opt/suricata135/etc/
sudo cp ../reference.config /opt/suricata135/etc/
sudo cp ../classification.config /opt/suricata135/etc/
make distclean

./configure LD_RUN_PATH="/opt/pcre-8.31/lib:/usr/lib:/usr/local/lib" --enable-pcre-jit --with-libpcre-libraries=/opt/pcre-8.31/lib/ --with-libpcre-includes=/opt/pcre-8.31/include/ --enable-profiling --prefix=/opt/suricata135JIT/ --with-libnss-includes=/usr/include/nss --with-libnss-libs=/usr/lib/nss --with-libnspr-includes=/usr/include/nspr --with-libnspr-libraries=/usr/lib/nspr && make -j && sudo make install
sudo cp suricata.yaml /opt/suricata135JIT/etc/
sudo cp ../reference.config /opt/suricata135JIT/etc/
sudo cp ../classification.config /opt/suricata135JIT/etc/
cd ..

tar -xzvf suricata-1.4.tar.gz
cd suricata-1.4
./configure --enable-profiling --prefix=/opt/suricata14/ --with-libnss-includes=/usr/include/nss --with-libnss-libs=/usr/lib/nss --with-libnspr-includes=/usr/include/nspr --with-libnspr-libraries=/usr/lib/nspr && make -j && sudo make install
sudo cp suricata.yaml /opt/suricata14/etc/
sudo cp ../reference.config /opt/suricata14/etc/
sudo cp ../classification.config /opt/suricata14/etc/
make distclean

./configure LD_RUN_PATH="/opt/pcre-8.31/lib:/opt/lib/:/usr/lib:/usr/local/lib" --enable-pcre-jit --with-libpcre-libraries=/opt/pcre-8.31/lib/ --with-libpcre-includes=/opt/pcre-8.31/include/ --enable-profiling --prefix=/opt/suricata/ --with-libnss-includes=/usr/include/nss --with-libnss-libs=/usr/lib/nss --with-libnspr-includes=/usr/include/nspr --with-libnspr-libraries=/usr/lib/nspr --enable-luajit --with-libluajit-includes=/opt/include/luajit-2.0/ --with-libluajit-libraries=/opt/lib/
sudo cp suricata.yaml /opt/suricata14JIT/etc/
sudo cp ../reference.config /opt/suricata14JIT/etc/
sudo cp ../classification.config /opt/suricata14JIT/etc/
cd ..

tar -xzvf libdnet-1.11.tar.gz
cd libdnet-1.11
./configure --prefix=/opt/libdnet111/
make -j && sudo make install
cd ..

tar -xzvf daq-0.5.tar.gz
cd daq-0.5
./configure --prefix=/opt/snort2904/ && make -j && sudo make install
make distclean
./configure --prefix=/opt/snort2905/ && make -j && sudo make install
cd ..

tar -xzvf snort-2.9.0.4.tar.gz
cd snort-2.9.0.4
PATH="/opt/snort2904/bin:$PATH" ./configure  --enable-ipv6 --enable-gre --enable-mpls --with-dnet-includes=/opt/libdnet111/include/ --with-dnet-libraries=/opt/libdnet111/lib/ --enable-targetbased --enable-decoder-preprocessor-rules --enable-ppm --enable-perfprofiling --enable-zlib LD_RUN_PATH="/opt/snort2904/lib:/opt/libdnet111/lib:/usr/lib:/usr/local/lib" --prefix=/opt/snort2904/ --with-daq-includes=/opt/snort2904/include/ --with-daq-libraries=/opt/snort2904/lib/ && make -j && sudo make install
sudo cp etc/* /opt/snort2904/etc/
cd ..

tar -xzvf snort-2.9.0.5.tar.gz
cd snort-2.9.0.5
PATH="/opt/snort2905/bin:$PATH" ./configure  --enable-ipv6 --enable-gre --enable-mpls --with-dnet-includes=/opt/libdnet111/include/ --with-dnet-libraries=/opt/libdnet111/lib/ --enable-targetbased --enable-decoder-preprocessor-rules --enable-ppm --enable-perfprofiling --enable-zlib LD_RUN_PATH="/opt/snort2905/lib:/opt/libdnet111/lib:/usr/lib:/usr/local/lib" --prefix=/opt/snort2905/ --with-daq-includes=/opt/snort2905/include/ --with-daq-libraries=/opt/snort2905/lib/ && make -j && sudo make install
sudo cp etc/* /opt/snort2905/etc/
cd ..

tar -xzvf daq-0.6.2.tar.gz
cd daq-0.6.2
./configure --prefix=/opt/snort2922/ && make -j && sudo make install
make distclean
./configure --prefix=/opt/snort2923/ && make -j && sudo make install
cd ..

tar -xzvf snort-2.9.2.2.tar.gz
cd snort-2.9.2.2
PATH="/opt/snort2922/bin:$PATH" ./configure --enable-ipv6 --enable-gre --enable-mpls --with-dnet-includes=/opt/libdnet111/include/ --with-dnet-libraries=/opt/libdnet111/lib/ --enable-targetbased --enable-decoder-preprocessor-rules --enable-ppm --enable-perfprofiling --enable-zlib --enable-active-response --enable-normalizer --enable-reload --enable-react --enable-flexresp3 LD_RUN_PATH="/opt/snort2922/lib:/opt/libdnet111/lib:/usr/lib:/usr/local/lib" --prefix=/opt/snort2922/ --with-daq-includes=/opt/snort2922/include/ --with-daq-libraries=/opt/snort2922/lib/ && make -j && sudo make install
sudo cp etc/* /opt/snort2922/etc/
cd ..

tar -xzvf snort-2.9.2.3.tar.gz
cd snort-2.9.2.3
PATH="/opt/snort2923/bin:$PATH" ./configure --enable-ipv6 --enable-gre --enable-mpls --with-dnet-includes=/opt/libdnet111/include/ --with-dnet-libraries=/opt/libdnet111/lib/ --enable-targetbased --enable-decoder-preprocessor-rules --enable-ppm --enable-perfprofiling --enable-zlib --enable-active-response --enable-normalizer --enable-reload --enable-react --enable-flexresp3 LD_RUN_PATH="/opt/snort2923/lib:/opt/libdnet111/lib:/usr/lib:/usr/local/lib" --prefix=/opt/snort2923/ --with-daq-includes=/opt/snort2923/include/ --with-daq-libraries=/opt/snort2923/lib/ && make -j && sudo make install
sudo cp etc/* /opt/snort2923/etc/
cd ..

tar -xzvf daq-1.1.1.tar.gz
cd daq-1.1.1
./configure --prefix=/opt/snort293/ && make -j && sudo make install
make distclean
./configure --prefix=/opt/snort2931/ && make -j && sudo make install
cd ..


tar -xzvf snort-2.9.3.tar.gz
cd snort-2.9.3
PATH="/opt/snort293/bin:$PATH" ./configure --enable-ipv6 --enable-gre --enable-mpls --with-dnet-includes=/opt/libdnet111/include/ --with-dnet-libraries=/opt/libdnet111/lib/ --enable-targetbased --enable-decoder-preprocessor-rules --enable-ppm --enable-perfprofiling --enable-zlib --enable-active-response --enable-normalizer --enable-reload --enable-react --enable-flexresp3 LD_RUN_PATH="/opt/snort293/lib:/opt/libdnet111/lib:/usr/lib:/usr/local/lib" --prefix=/opt/snort293/ --with-daq-includes=/opt/snort293/include/ --with-daq-libraries=/opt/snort293/lib/ && make -j && sudo make install
sudo cp etc/* /opt/snort293/etc/
cd ..

tar -xzvf snort-2.9.3.1.tar.gz
cd snort-2.9.3.1
PATH="/opt/snort2931/bin:$PATH" ./configure --enable-ipv6 --enable-gre --enable-mpls --with-dnet-includes=/opt/libdnet111/include/ --with-dnet-libraries=/opt/libdnet111/lib/ --enable-targetbased --enable-decoder-preprocessor-rules --enable-ppm --enable-perfprofiling --enable-zlib --enable-active-response --enable-normalizer --enable-reload --enable-react --enable-flexresp3 LD_RUN_PATH="/opt/snort2931/lib:/opt/libdnet111/lib:/usr/lib:/usr/local/lib" --prefix=/opt/snort2931/ --with-daq-includes=/opt/snort2931/include/ --with-daq-libraries=/opt/snort2931/lib/ && make -j && sudo make install
sudo cp etc/* /opt/snort2931/etc/
cd ..

tar -xzvf daq-2.0.0.tar.gz
cd daq-2.0.0
./configure --prefix=/opt/snort294/ && make -j && sudo make install
cd ..

tar -xzvf snort-2.9.4.tar.gz
cd snort-2.9.4
PATH="/opt/snort294/bin:$PATH" ./configure --enable-ipv6 --enable-gre --enable-mpls --with-dnet-includes=/opt/libdnet111/include/ --with-dnet-libraries=/opt/libdnet111/lib/ --enable-targetbased --enable-decoder-preprocessor-rules --enable-ppm --enable-perfprofiling --enable-zlib --enable-active-response --enable-normalizer --enable-reload --enable-react --enable-flexresp3 LD_RUN_PATH="/opt/snort294/lib:/opt/libdnet111/lib:/usr/lib:/usr/local/lib" --prefix=/opt/snort294/ --with-daq-includes=/opt/snort294/include/ --with-daq-libraries=/opt/snort294/lib/ && make -j && sudo make install
sudo cp etc/* /opt/snort294/etc/
cd ..

sudo python ./gunstar-maker.py
tar -xzvf pulledpork-0.6.1.tar.gz
cd pulledpork-0.6.1
patch -p1 < ../ppconfigs/pulledpork-etpro-fix.diff
sudo cp -f pulledpork.pl /usr/local/bin/
cd ..
sudo cp ruleupdates.sh /usr/local/bin/

CURRENT_USER=`whoami`
sudo chown $CURRENT_USER /opt/snort* -Rf
sudo chown $CURRENT_USER /opt/suricata* -Rf

rm daq-0.6.2 -Rf
rm daq-0.5 -Rf
rm daq-1.1.1 -Rf
rm daq-2.0.0 -Rf
rm snort-2.8.4.1 -Rf
rm snort-2.8.6.1 -Rf
rm snort-2.9.0.4 -Rf
rm snort-2.9.0.5 -Rf 
rm snort-2.9.2.2 -Rf
rm snort-2.9.2.3 -Rf
rm snort-2.9.3 -Rf
rm snort-2.9.3.1 -Rf
rm snort-2.9.4 -Rf
rm pcre-8.31 -Rf
rm suricata-1.2.1 -Rf 
rm suricata-1.3 -Rf
rm suricata-1.3.1 -Rf
rm suricata-1.3.5 -Rf
rm suricata-1.4 -Rf
rm pulledpork-0.6.1 -Rf
rm libdnet-1.11 -Rf
rm LuaJIT-2.0.0 -Rf
rm lua-zlib -Rf
