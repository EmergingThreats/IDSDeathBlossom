#/bin/sh
sudo mkdir -p /opt/snort2841/{bin,lib,include/linux,sbin,etc/etpro,etc/etopen,var/log}
sudo mkdir -p /opt/snort2861/{bin,lib,include/linux,sbin,etc/etpro,etc/etopen,var/log}
sudo mkdir -p /opt/snort2904/{bin,lib,include/linux,sbin,etc/etpro,etc/etopen,var/log}
sudo mkdir -p /opt/snort2905/{bin,lib,include/linux,sbin,etc/etpro,etc/etopen,var/log}
sudo mkdir -p /opt/snort2922/{bin,lib,include/linux,sbin,etc/etpro,etc/etopen,var/log}
sudo mkdir -p /opt/snort2923/{bin,lib,include/linux,sbin,etc/etpro,etc/etopen,var/log}
sudo mkdir -p /opt/suricata121/{bin,lib,include/linux,sbin,etc/etpro,etc/etopen,var/log}
sudo mkdir -p /opt/suricata13b2/{bin,lib,include/linux,sbin,etc/etpro,etc/etopen,var/log}
sudo mkdir -p /opt/suricata13b2JIT/{bin,lib,include/linux,sbin,etc/etpro,etc/etopen,var/log}

sudo apt-get install build-essential libnspr4-dev libnss3-dev libwww-Perl libcrypt-ssleay-perl python-dev python-scapy python-yaml bison libpcre3-dev bison flex libpcap-ruby libdumbnet-dev autotools-dev libnet1-dev libpcap-dev libyaml-dev libnetfilter-queue-dev libprelude-dev zlib1g-dev  libz-dev libcap-ng-dev libmagic-dev

tar -xzvf snort_2.8.4.1.orig.tar.gz
cd snort-2.8.4.1
./configure --enable-perfprofiling --prefix=/opt/snort2841/ && make && sudo make install
sudo cp etc/* /opt/snort2841/etc/
cd ..

tar -xzvf snort-2.8.6.1.tar.gz
cd snort-2.8.6.1
./configure --enable-perfprofiling --prefix=/opt/snort2861/ && make && sudo make install
sudo cp etc/* /opt/snort2861/etc/
cd ..

tar -xzvf pcre-8.30.tar.gz
cd pcre-8.30
./configure --prefix=/opt/pcre-8.30/ --enable-jit --enable-utf8 --enable-unicode-properties
make
sudo make install
cd ..

tar -xzvf suricata-1.2.1.tar.gz
cd suricata-1.2.1
./configure --enable-profiling --prefix=/opt/suricata121/ --with-libnss-includes=/usr/include/nss --with-libnss-libs=/usr/lib/nss --with-libnspr-includes=/usr/include/nspr --with-libnspr-libraries=/usr/lib/nspr && make && sudo make install
sudo cp suricata.yaml /opt/suricata121/etc/
sudo cp reference.config /opt/suricata121/etc/
sudo cp classification.config /opt/suricata121/etc/
cd ..

tar -xzvf suricata-1.3beta2.tar.gz
cd suricata-1.3beta2
./configure --enable-profiling --prefix=/opt/suricata13b2/ --with-libnss-includes=/usr/include/nss --with-libnss-libs=/usr/lib/nss --with-libnspr-includes=/usr/include/nspr --with-libnspr-libraries=/usr/lib/nspr && make && sudo make install
sudo cp suricata.yaml /opt/suricata13b2/etc/
sudo cp reference.config /opt/suricata13b2/etc/
sudo cp classification.config /opt/suricata13b2/etc/
make distclean
./configure LD_RUN_PATH="/opt/pcre-8.30/lib:/usr/lib:/usr/local/lib" --enable-pcre-jit --with-libpcre-libraries=/opt/pcre-8.30/lib/ --with-libpcre-includes=/opt/pcre-8.30/include/ --enable-profiling --prefix=/opt/suricata13b2JIT/ --with-libnss-includes=/usr/include/nss --with-libnss-libs=/usr/lib/nss --with-libnspr-includes=/usr/include/nspr --with-libnspr-libraries=/usr/lib/nspr && make && sudo make install
sudo cp suricata.yaml /opt/suricata13b2JIT/etc/
sudo cp reference.config /opt/suricata13b2JIT/etc/
sudo cp classification.config /opt/suricata13b2JIT/etc/
cd ..

tar -xzvf daq-0.5.tar.gz
cd daq-0.5
./configure --prefix=/opt/snort2904/ && make && sudo make install
make clean
./configure --prefix=/opt/snort2905/ && make && sudo make install
cd ..

tar -xzvf snort-2.9.0.4.tar.gz
cd snort-2.9.0.4
PATH="/opt/snort2904/bin:$PATH" ./configure  --enable-ipv6 --enable-gre --enable-mpls --enable-targetbased --enable-decoder-preprocessor-rules --enable-ppm --enable-perfprofiling --enable-zlib LD_RUN_PATH="/opt/snort2904/lib:/usr/lib:/usr/local/lib" --prefix=/opt/snort2904/ --with-daq-includes=/opt/snort2904/include/ --with-daq-libraries=/opt/snort2904/lib/ && make && sudo make install
sudo cp etc/* /opt/snort2904/etc/
cd ..

tar -xzvf snort-2.9.0.5.tar.gz
cd snort-2.9.0.5
PATH="/opt/snort2905/bin:$PATH" ./configure  --enable-ipv6 --enable-gre --enable-mpls --enable-targetbased --enable-decoder-preprocessor-rules --enable-ppm --enable-perfprofiling --enable-zlib LD_RUN_PATH="/opt/snort2905/lib:/usr/lib:/usr/local/lib" --prefix=/opt/snort2905/ --with-daq-includes=/opt/snort2905/include/ --with-daq-libraries=/opt/snort2905/lib/ && make && sudo make install
sudo cp etc/* /opt/snort2905/etc/
cd ..

tar -xzvf daq-0.6.2.tar.gz
cd daq-0.6.2
./configure --prefix=/opt/snort2922/ && make && sudo make install
./configure --prefix=/opt/snort2923/ && make && sudo make install
cd ..

tar -xzvf snort-2.9.2.2.tar.gz
cd snort-2.9.2.2
PATH="/opt/snort2922/bin:$PATH" ./configure --enable-ipv6 --enable-gre --enable-mpls --enable-targetbased --enable-decoder-preprocessor-rules --enable-ppm --enable-perfprofiling --enable-zlib --enable-active-response --enable-normalizer --enable-reload --enable-react --enable-flexresp3 LD_RUN_PATH="/opt/snort2922/lib:/usr/lib:/usr/local/lib" --prefix=/opt/snort2922/ --with-daq-includes=/opt/snort2922/include/ --with-daq-libraries=/opt/snort2922/lib/ && make && sudo make install
sudo cp etc/* /opt/snort2922/etc/
cd ..

tar -xzvf snort-2.9.2.3.tar.gz
cd snort-2.9.2.3
PATH="/opt/snort2923/bin:$PATH" ./configure --enable-ipv6 --enable-gre --enable-mpls --enable-targetbased --enable-decoder-preprocessor-rules --enable-ppm --enable-perfprofiling --enable-zlib --enable-active-response --enable-normalizer --enable-reload --enable-react --enable-flexresp3 LD_RUN_PATH="/opt/snort2923/lib:/usr/lib:/usr/local/lib" --prefix=/opt/snort2923/ --with-daq-includes=/opt/snort2923/include/ --with-daq-libraries=/opt/snort2923/lib/ && make && sudo make install
sudo cp etc/* /opt/snort2923/etc/
cd ..

tar -xzvf pulledpork-0.6.1.tar.gz
cd pulledpork-0.6.1
patch -p1 < ../pulledpork-etpro-fix.diff
sudo cp -f pulledpork.pl /usr/local/bin/
sudo cp -f etc/* /opt/snort2841/etc/etopen/
sudo cp -f etc/* /opt/snort2861/etc/etopen/
sudo cp -f etc/* /opt/snort2904/etc/etopen/
sudo cp -f etc/* /opt/snort2905/etc/etopen/
sudo cp -f etc/* /opt/snort2922/etc/etopen/
sudo cp -f etc/* /opt/snort2923/etc/etopen/
sudo cp -f etc/* /opt/suricata121/etc/etopen/
sudo cp -f etc/* /opt/suricata13b2/etc/etopen/
sudo cp -f etc/* /opt/suricata13b2JIT/etc/etopen/
sudo cp ../pp-snort-2.8.4.1-ETOPEN.config /opt/snort2841/etc/etopen/
sudo cp ../pp-snort-2.8.6.1-ETOPEN.config /opt/snort2861/etc/etopen/
sudo cp ../pp-snort-2.9.0.4-ETOPEN.config /opt/snort2904/etc/etopen/
sudo cp ../pp-snort-2.9.0.5-ETOPEN.config /opt/snort2905/etc/etopen/
sudo cp ../pp-snort-2.9.2.2-ETOPEN.config /opt/snort2922/etc/etopen/
sudo cp ../pp-snort-2.9.2.3-ETOPEN.config /opt/snort2923/etc/etopen/
sudo cp ../pp-suricata-1.2.1-ETOPEN.config /opt/suricata121/etc/etopen/
sudo cp ../pp-suricata-1.3b2-ETOPEN.config /opt/suricata13b2/etc/etopen/
sudo cp ../pp-suricata-1.3b2JIT-ETOPEN.config /opt/suricata13b2JIT/etc/etopen/
cd ..  
CURRENT_USER=`whoami`
sudo chown $CURRENT_USER /opt/snort* -Rf
sudo chown $CURRENT_USER /opt/suricata* -Rf

rm daq-0.6.2 -Rf
rm daq-0.5 -Rf
rm snort-2.8.4.1 -Rf
rm snort-2.8.6.1 -Rf
rm snort-2.9.0.4 -Rf
rm snort-2.9.0.5 -Rf 
rm snort-2.9.2.2 -Rf
rm snort-2.9.2.3 -Rf
rm pcre-8.30 -Rf
rm suricata-1.2.1 -Rf 
rm suricata-1.3beta2 -Rf
rm pulled-pork-0.6.1 -Rf
