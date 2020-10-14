#!/bin/bash

# enable below if needed for troubleshooting
#set -e 

usage()
{
cat << EOF

usage: $0 options

##############################
## IDSDB add engine options ##
##############################

./idsdb_install_all_engines.sh

Mass IDSDB install of all engines Suricata/Snort/Suricata 
with all necessary templates/rulesets updates/downloads and set up needed.

OPTIONS:
   -h      Help info
   -o      Oinkcode to use (if desired) for ETPro ruleset. If not provided ETOpen will be used.
           
   
   EXAMPLES: 
   ./ idsdb_install_all_engines.sh -o 1234567890
   The example above will use oinkcode 1234567890 for the ruleset download/set up/update  of all engines (Suricata and Snort)
   
    ./ idsdb_install_all_engines.sh
   The example above will not use an oinkcode for the ruleset download/set up 
      
   
EOF
}

while getopts “ho:” OPTION
do
     case $OPTION in
         h)
             usage
             exit 1
             ;;
         o)
             oinkcode=$OPTARG
             if ! [[ "${oinkcode}" =~ ^[a-zA-Z0-9]*$ ]]; 
             then
               echo -e "\n Please supply a correct oinkcode  - no spaces and/or special characters allowed \n"
               usage
               exit 1;
             fi
             ;;
         ?)
             oinkcode=
             echo "Not expected options supplied "
             exit 1;
             ;;

     esac
done
shift $((OPTIND -1))

#concurrent processes 
processes=$(getconf _NPROCESSORS_ONLN)

sudo mkdir -p /opt/snort2905/{bin,lib,include/linux,sbin,etc/etpro,etc/etproenall,etc/etopen,etc/etopenenall,/etc/test,var/log,etc/sanitize/sopen,etc/sanitize/spro}
sudo mkdir -p /opt/snort2923/{bin,lib,include/linux,sbin,etc/etpro,etc/etproenall,etc/etopen,etc/etopenenall,/etc/test,var/log,etc/sanitize/sopen,etc/sanitize/spro}
sudo mkdir -p /opt/snort2931/{bin,lib,include/linux,sbin,etc/etpro,etc/etproenall,etc/etopen,etc/etopenenall,/etc/test,var/log,etc/sanitize/sopen,etc/sanitize/spro}
sudo mkdir -p /opt/snort2946/{bin,lib,include/linux,sbin,etc/etpro,etc/etproenall,etc/etopen,etc/etopenenall,/etc/test,var/log,etc/sanitize/sopen,etc/sanitize/spro}
sudo mkdir -p /opt/snort2956/{bin,lib,include/linux,sbin,etc/etpro,etc/etproenall,etc/etopen,etc/etopenenall,/etc/test,var/log,etc/sanitize/sopen,etc/sanitize/spro}
sudo mkdir -p /opt/snort2960/{bin,lib,include/linux,sbin,etc/etpro,etc/etproenall,etc/etopen,etc/etopenenall,/etc/test,var/log,etc/sanitize/sopen,etc/sanitize/spro}
sudo mkdir -p /opt/snort2961/{bin,lib,include/linux,sbin,etc/etpro,etc/etproenall,etc/etopen,etc/etopenenall,/etc/test,var/log,etc/sanitize/sopen,etc/sanitize/spro}
sudo mkdir -p /opt/snort2962/{bin,lib,include/linux,sbin,etc/etpro,etc/etproenall,etc/etopen,etc/etopenenall,/etc/test,var/log,etc/sanitize/sopen,etc/sanitize/spro}
sudo mkdir -p /opt/snort2970/{bin,lib,include/linux,sbin,etc/etpro,etc/etproenall,etc/etopen,etc/etopenenall,/etc/test,var/log,etc/sanitize/sopen,etc/sanitize/spro}
sudo mkdir -p /opt/snort2972/{bin,lib,include/linux,sbin,etc/etpro,etc/etproenall,etc/etopen,etc/etopenenall,/etc/test,var/log,etc/sanitize/sopen,etc/sanitize/spro}
sudo mkdir -p /opt/snort2973/{bin,lib,include/linux,sbin,etc/etpro,etc/etproenall,etc/etopen,etc/etopenenall,/etc/test,var/log,etc/sanitize/sopen,etc/sanitize/spro}
sudo mkdir -p /opt/snort2975/{bin,lib,include/linux,sbin,etc/etpro,etc/etproenall,etc/etopen,etc/etopenenall,/etc/test,var/log,etc/sanitize/sopen,etc/sanitize/spro}
sudo mkdir -p /opt/snort2976/{bin,lib,include/linux,sbin,etc/etpro,etc/etproenall,etc/etopen,etc/etopenenall,/etc/test,var/log,etc/sanitize/sopen,etc/sanitize/spro}
sudo mkdir -p /opt/snort2980/{bin,lib,include/linux,sbin,etc/etpro,etc/etproenall,etc/etopen,etc/etopenenall,/etc/test,var/log,etc/sanitize/sopen,etc/sanitize/spro}
sudo mkdir -p /opt/snort2982/{bin,lib,include/linux,sbin,etc/etpro,etc/etproenall,etc/etopen,etc/etopenenall,/etc/test,var/log,etc/sanitize/sopen,etc/sanitize/spro}
sudo mkdir -p /opt/snort2983/{bin,lib,include/linux,sbin,etc/etpro,etc/etproenall,etc/etopen,etc/etopenenall,/etc/test,var/log,etc/sanitize/sopen,etc/sanitize/spro}
sudo mkdir -p /opt/snort2990/{bin,lib,include/linux,sbin,etc/etpro,etc/etproenall,etc/etopen,etc/etopenenall,/etc/test,var/log,etc/sanitize/sopen,etc/sanitize/spro}
sudo mkdir -p /opt/snort2911/{bin,lib,include/linux,sbin,etc/etpro,etc/etproenall,etc/etopen,etc/etopenenall,/etc/test,var/log,etc/sanitize/sopen,etc/sanitize/spro}
sudo mkdir -p /opt/snort29111/{bin,lib,include/linux,sbin,etc/etpro,etc/etproenall,etc/etopen,etc/etopenenall,/etc/test,var/log,etc/sanitize/sopen,etc/sanitize/spro}
sudo mkdir -p /opt/snort2912/{bin,lib,include/linux,sbin,etc/etpro,etc/etproenall,etc/etopen,etc/etopenenall,/etc/test,var/log,etc/sanitize/sopen,etc/sanitize/spro}


sudo mkdir -p /opt/suricata400/{bin,lib,include/linux,sbin,etc/etpro,etc/etproenall,etc/etopen,etc/etopenenall,/etc/test,var/run/suricata,var/log,etc/sanitize/sopen,etc/sanitize/spro}
sudo mkdir -p /opt/suricata401/{bin,lib,include/linux,sbin,etc/etpro,etc/etproenall,etc/etopen,etc/etopenenall,/etc/test,var/run/suricata,var/log,etc/sanitize/sopen,etc/sanitize/spro}
sudo mkdir -p /opt/suricata402/{bin,lib,include/linux,sbin,etc/etpro,etc/etproenall,etc/etopen,etc/etopenenall,/etc/test,var/run/suricata,var/log,etc/sanitize/sopen,etc/sanitize/spro}
sudo mkdir -p /opt/suricata403/{bin,lib,include/linux,sbin,etc/etpro,etc/etproenall,etc/etopen,etc/etopenenall,/etc/test,var/run/suricata,var/log,etc/sanitize/sopen,etc/sanitize/spro}
sudo mkdir -p /opt/suricata404/{bin,lib,include/linux,sbin,etc/etpro,etc/etproenall,etc/etopen,etc/etopenenall,/etc/test,var/run/suricata,var/log,etc/sanitize/sopen,etc/sanitize/spro}
sudo mkdir -p /opt/suricata405/{bin,lib,include/linux,sbin,etc/etpro,etc/etproenall,etc/etopen,etc/etopenenall,/etc/test,var/run/suricata,var/log,etc/sanitize/sopen,etc/sanitize/spro}
sudo mkdir -p /opt/suricata410/{bin,lib,include/linux,sbin,etc/etpro,etc/etproenall,etc/etopen,etc/etopenenall,/etc/test,var/run/suricata,var/log,etc/sanitize/sopen,etc/sanitize/spro}
sudo mkdir -p /opt/suricata503/{bin,lib,include/linux,sbin,etc/etpro,etc/etproenall,etc/etopen,etc/etopenenall,/etc/test,var/run/suricata,var/log,etc/sanitize/sopen,etc/sanitize/spro}
sudo mkdir -p /opt/suricata600/{bin,lib,include/linux,sbin,etc/etpro,etc/etproenall,etc/etopen,etc/etopenenall,/etc/test,var/run/suricata,var/log,etc/sanitize/sopen,etc/sanitize/spro}
sudo mkdir -p /opt/et-luajit-scripts


tar -xzvf engine-sources/suricata/suricata-4.0.0.tar.gz -C engine-sources/suricata
cd engine-sources/suricata/suricata-4.0.0
./configure --enable-lua --enable-profiling --prefix=/opt/suricata400/ --with-libnss-includes=/usr/include/nss --with-libnss-libs=/usr/lib/nss --with-libnspr-includes=/usr/include/nspr --with-libnspr-libraries=/usr/lib/nspr && make -j ${processes} && sudo make install
sudo cp suricata.yaml /opt/suricata400/etc/
sudo cp reference.config /opt/suricata400/etc/
sudo cp classification.config /opt/suricata400/etc/
sudo cp threshold.config /opt/suricata400/etc/
cd ../../../

tar -xzvf engine-sources/suricata/suricata-4.0.1.tar.gz -C engine-sources/suricata
cd engine-sources/suricata/suricata-4.0.1
./configure --enable-lua --enable-profiling --prefix=/opt/suricata401/ --with-libnss-includes=/usr/include/nss --with-libnss-libs=/usr/lib/nss --with-libnspr-includes=/usr/include/nspr --with-libnspr-libraries=/usr/lib/nspr && make -j ${processes} && sudo make install
sudo cp suricata.yaml /opt/suricata401/etc/
sudo cp reference.config /opt/suricata401/etc/
sudo cp classification.config /opt/suricata401/etc/
sudo cp threshold.config /opt/suricata401/etc/
cd ../../../

tar -xzvf engine-sources/suricata/suricata-4.0.2.tar.gz -C engine-sources/suricata
cd engine-sources/suricata/suricata-4.0.2
./configure --enable-lua --enable-profiling --prefix=/opt/suricata402/ --with-libnss-includes=/usr/include/nss --with-libnss-libs=/usr/lib/nss --with-libnspr-includes=/usr/include/nspr --with-libnspr-libraries=/usr/lib/nspr && make -j ${processes} && sudo make install
sudo cp suricata.yaml /opt/suricata402/etc/
sudo cp reference.config /opt/suricata402/etc/
sudo cp classification.config /opt/suricata402/etc/
sudo cp threshold.config /opt/suricata402/etc/
cd ../../../

tar -xzvf engine-sources/suricata/suricata-4.0.3.tar.gz -C engine-sources/suricata
cd engine-sources/suricata/suricata-4.0.3
./configure --enable-lua --enable-profiling --prefix=/opt/suricata403/ --with-libnss-includes=/usr/include/nss --with-libnss-libs=/usr/lib/nss --with-libnspr-includes=/usr/include/nspr --with-libnspr-libraries=/usr/lib/nspr && make -j ${processes} && sudo make install
sudo cp suricata.yaml /opt/suricata403/etc/
sudo cp reference.config /opt/suricata403/etc/
sudo cp classification.config /opt/suricata403/etc/
sudo cp threshold.config /opt/suricata403/etc/
cd ../../../

tar -xzvf engine-sources/suricata/suricata-4.0.4.tar.gz -C engine-sources/suricata
cd engine-sources/suricata/suricata-4.0.4
./configure --enable-lua --enable-profiling --prefix=/opt/suricata404/ --with-libnss-includes=/usr/include/nss --with-libnss-libs=/usr/lib/nss --with-libnspr-includes=/usr/include/nspr --with-libnspr-libraries=/usr/lib/nspr && make -j ${processes} && sudo make install
sudo cp suricata.yaml /opt/suricata404/etc/
sudo cp reference.config /opt/suricata404/etc/
sudo cp classification.config /opt/suricata404/etc/
sudo cp threshold.config /opt/suricata404/etc/
cd ../../../

tar -xzvf engine-sources/suricata/suricata-4.0.5.tar.gz -C engine-sources/suricata
cd engine-sources/suricata/suricata-4.0.5
./configure --enable-lua --enable-profiling --prefix=/opt/suricata405/ --with-libnss-includes=/usr/include/nss --with-libnss-libs=/usr/lib/nss --with-libnspr-includes=/usr/include/nspr --with-libnspr-libraries=/usr/lib/nspr && make -j ${processes} && sudo make install
sudo cp suricata.yaml /opt/suricata405/etc/
sudo cp reference.config /opt/suricata405/etc/
sudo cp classification.config /opt/suricata405/etc/
sudo cp threshold.config /opt/suricata405/etc/
cd ../../../

tar -xzvf engine-sources/suricata/suricata-4.1.0.tar.gz -C engine-sources/suricata
cd engine-sources/suricata/suricata-4.1.0
./configure --enable-lua --enable-profiling --prefix=/opt/suricata410/ --with-libnss-includes=/usr/include/nss --with-libnss-libs=/usr/lib/nss --with-libnspr-includes=/usr/include/nspr --with-libnspr-libraries=/usr/lib/nspr && make -j ${processes} && sudo make install
sudo cp suricata.yaml /opt/suricata410/etc/
sudo cp reference.config /opt/suricata410/etc/
sudo cp classification.config /opt/suricata410/etc/
sudo cp threshold.config /opt/suricata410/etc/
cd ../../../

tar -xzvf engine-sources/suricata/suricata-5.0.3.tar.gz -C engine-sources/suricata
cd engine-sources/suricata/suricata-5.0.3
./configure --enable-lua --enable-profiling --prefix=/opt/suricata503/ --with-libnss-includes=/usr/include/nss --with-libnss-libs=/usr/lib/nss --with-libnspr-includes=/usr/include/nspr --with-libnspr-libraries=/usr/lib/nspr && make -j ${processes} && sudo make install
sudo cp suricata.yaml /opt/suricata503/etc/
sudo cp etc/reference.config /opt/suricata503/etc/
sudo cp etc/classification.config /opt/suricata503/etc/
sudo cp threshold.config /opt/suricata503/etc/
cd ../../../

tar -xzvf engine-sources/suricata/suricata-6.0.0.tar.gz -C engine-sources/suricata
cd engine-sources/suricata/suricata-6.0.0
./configure --enable-lua --enable-profiling --prefix=/opt/suricata503/ --with-libnss-includes=/usr/include/nss --with-libnss-libs=/usr/lib/nss --with-libnspr-includes=/usr/include/nspr --with-libnspr-libraries=/usr/lib/nspr && make -j ${processes} && sudo make install
sudo cp suricata.yaml /opt/suricata600/etc/
sudo cp etc/reference.config /opt/suricata600/etc/
sudo cp etc/classification.config /opt/suricata600/etc/
sudo cp threshold.config /opt/suricata600/etc/
cd ../../../

tar -xzvf engine-sources/daq/daq-0.5.tar.gz -C engine-sources/daq
cd engine-sources/daq/daq-0.5
autoreconf -f -i
./configure --prefix=/opt/snort2905/ && make && sudo make install
cd ../../../

tar -xzvf engine-sources/snort/snort-2.9.0.5.tar.gz -C engine-sources/snort
cd engine-sources/snort/snort-2.9.0.5
PATH="/opt/snort2905/bin:$PATH" ./configure  --enable-ipv6 --enable-gre --enable-mpls --with-dnet-includes=/opt/libdnet111/include/ --with-dnet-libraries=/opt/libdnet111/lib/ --enable-targetbased --enable-decoder-preprocessor-rules --enable-ppm --enable-perfprofiling --enable-zlib LD_RUN_PATH="/opt/snort2905/lib:/opt/libdnet111/lib:/usr/lib:/usr/local/lib" --prefix=/opt/snort2905/ --with-daq-includes=/opt/snort2905/include/ --with-daq-libraries=/opt/snort2905/lib/ && make -j ${processes} && sudo make install
sudo cp etc/* /opt/snort2905/etc/
cd ../../../

tar -xzvf engine-sources/daq/daq-0.6.2.tar.gz -C engine-sources/daq
cd engine-sources/daq/daq-0.6.2
autoreconf -f -i 
./configure --prefix=/opt/snort2923/ && make && sudo make install
cd ../../../

tar -xzvf engine-sources/snort/snort-2.9.2.3.tar.gz -C engine-sources/snort
cd engine-sources/snort/snort-2.9.2.3
PATH="/opt/snort2923/bin:$PATH" ./configure --enable-ipv6 --enable-gre --enable-mpls --with-dnet-includes=/opt/libdnet111/include/ --with-dnet-libraries=/opt/libdnet111/lib/ --enable-targetbased --enable-decoder-preprocessor-rules --enable-ppm --enable-perfprofiling --enable-zlib --enable-active-response --enable-normalizer --enable-reload --enable-react --enable-flexresp3 LD_RUN_PATH="/opt/snort2923/lib:/opt/libdnet111/lib:/usr/lib:/usr/local/lib" --prefix=/opt/snort2923/ --with-daq-includes=/opt/snort2923/include/ --with-daq-libraries=/opt/snort2923/lib/ && make -j ${processes} && sudo make install
sudo cp etc/* /opt/snort2923/etc/
cd ../../../

tar -xzvf engine-sources/daq/daq-1.1.1.tar.gz -C engine-sources/daq
cd engine-sources/daq/daq-1.1.1
autoreconf -f -i 
./configure --prefix=/opt/snort2931/ && make && sudo make install
cd ../../../

tar -xzvf engine-sources/snort/snort-2.9.3.1.tar.gz -C engine-sources/snort
cd engine-sources/snort/snort-2.9.3.1
PATH="/opt/snort2931/bin:$PATH" ./configure --enable-ipv6 --enable-gre --enable-mpls --with-dnet-includes=/opt/libdnet111/include/ --with-dnet-libraries=/opt/libdnet111/lib/ --enable-targetbased --enable-decoder-preprocessor-rules --enable-ppm --enable-perfprofiling --enable-zlib --enable-active-response --enable-normalizer --enable-reload --enable-react --enable-flexresp3 LD_RUN_PATH="/opt/snort2931/lib:/opt/libdnet111/lib:/usr/lib:/usr/local/lib" --prefix=/opt/snort2931/ --with-daq-includes=/opt/snort2931/include/ --with-daq-libraries=/opt/snort2931/lib/ && make -j ${processes} && sudo make install
sudo cp etc/* /opt/snort2931/etc/
cd ../../../

tar -xzvf engine-sources/daq/daq-2.0.2.tar.gz -C engine-sources/daq
cd engine-sources/daq/daq-2.0.2
./configure --prefix=/opt/daq202/ && make && sudo make install
cd ../../../

tar -xzvf engine-sources/snort/snort-2.9.4.6.tar.gz -C engine-sources/snort
cd engine-sources/snort/snort-2.9.4.6
PATH="/opt/daq202/bin:$PATH" ./configure --enable-ipv6 --enable-gre --enable-mpls --with-dnet-includes=/opt/libdnet111/include/ --with-dnet-libraries=/opt/libdnet111/lib/ --enable-targetbased --enable-decoder-preprocessor-rules --enable-ppm --enable-perfprofiling --enable-zlib --enable-active-response --enable-normalizer --enable-reload --enable-react --enable-flexresp3 LD_RUN_PATH="/opt/daq202/lib:/opt/snort2946/lib:/opt/libdnet111/lib:/usr/lib:/usr/local/lib" --prefix=/opt/snort2946/ --with-daq-includes=/opt/daq202/include/ --with-daq-libraries=/opt/daq202/lib/ && make -j ${processes} && sudo make install
sudo cp etc/* /opt/snort2946/etc/
cd ../../../

tar -xzvf engine-sources/snort/snort-2.9.5.6.tar.gz -C engine-sources/snort
cd engine-sources/snort/snort-2.9.5.6
PATH="/opt/daq202/bin:$PATH" ./configure --enable-ipv6 --enable-gre --enable-mpls --with-dnet-includes=/opt/libdnet111/include/ --with-dnet-libraries=/opt/libdnet111/lib/ --enable-targetbased --enable-decoder-preprocessor-rules --enable-ppm --enable-perfprofiling --enable-zlib --enable-active-response --enable-normalizer --enable-reload --enable-react --enable-flexresp3 LD_RUN_PATH="/opt/daq202/lib:/opt/snort2956/lib:/opt/libdnet111/lib:/usr/lib:/usr/local/lib" --prefix=/opt/snort2956/ --with-daq-includes=/opt/daq202/include/ --with-daq-libraries=/opt/daq202/lib/ && make -j ${processes} && sudo make install
sudo cp etc/* /opt/snort2956/etc/
cd ../../../

tar -xzvf engine-sources/snort/snort-2.9.6.0.tar.gz -C engine-sources/snort
cd engine-sources/snort/snort-2.9.6.0
PATH="/opt/daq202/bin:$PATH" ./configure --enable-ipv6 --enable-gre --enable-mpls --with-dnet-includes=/opt/libdnet111/include/ --with-dnet-libraries=/opt/libdnet111/lib/ --enable-targetbased --enable-decoder-preprocessor-rules --enable-ppm --enable-perfprofiling --enable-zlib --enable-active-response --enable-normalizer --enable-reload --enable-react --enable-flexresp3 LD_RUN_PATH="/opt/daq202/lib:/opt/snort2960/lib:/opt/libdnet111/lib:/usr/lib:/usr/local/lib" --prefix=/opt/snort2960/ --with-daq-includes=/opt/daq202/include/ --with-daq-libraries=/opt/daq202/lib/ && make -j ${processes} && sudo make install
sudo cp etc/* /opt/snort2960/etc/
cd ../../../

tar -xzvf engine-sources/snort/snort-2.9.6.1.tar.gz -C engine-sources/snort
cd engine-sources/snort/snort-2.9.6.1
PATH="/opt/daq202/bin:$PATH" ./configure --enable-ipv6 --enable-gre --enable-mpls --with-dnet-includes=/opt/libdnet111/include/ --with-dnet-libraries=/opt/libdnet111/lib/ --enable-targetbased --enable-decoder-preprocessor-rules --enable-ppm --enable-perfprofiling --enable-zlib --enable-active-response --enable-normalizer --enable-reload --enable-react --enable-flexresp3 LD_RUN_PATH="/opt/daq202/lib:/opt/snort2961/lib:/opt/libdnet111/lib:/usr/lib:/usr/local/lib" --prefix=/opt/snort2961/ --with-daq-includes=/opt/daq202/include/ --with-daq-libraries=/opt/daq202/lib/ && make -j ${processes} && sudo make install
sudo cp etc/* /opt/snort2961/etc/
cd ../../../

tar -xzvf engine-sources/snort/snort-2.9.6.2.tar.gz -C engine-sources/snort
cd engine-sources/snort/snort-2.9.6.2
PATH="/opt/daq202/bin:$PATH" ./configure --enable-ipv6 --enable-gre --enable-mpls --with-dnet-includes=/opt/libdnet111/include/ --with-dnet-libraries=/opt/libdnet111/lib/ --enable-targetbased --enable-decoder-preprocessor-rules --enable-ppm --enable-perfprofiling --enable-zlib --enable-active-response --enable-normalizer --enable-reload --enable-react --enable-flexresp3 LD_RUN_PATH="/opt/daq202/lib:/opt/snort2962/lib:/opt/libdnet111/lib:/usr/lib:/usr/local/lib" --prefix=/opt/snort2962/ --with-daq-includes=/opt/daq202/include/ --with-daq-libraries=/opt/daq202/lib/ && make -j ${processes} && sudo make install
sudo cp etc/* /opt/snort2962/etc/
cd ../../../

tar -xzvf engine-sources/daq/daq-2.0.4.tar.gz -C engine-sources/daq
cd engine-sources/daq/daq-2.0.4
./configure --prefix=/opt/daq204/ --with-dnet-includes=/opt/libdnet111/include/ --with-dnet-libraries=/opt/libdnet111/lib/ && make && sudo make install
cd ../../../

tar -xzvf engine-sources/snort/snort-2.9.7.0.tar.gz -C engine-sources/snort
cd engine-sources/snort/snort-2.9.7.0
PATH="/opt/daq204/bin:$PATH" ./configure --enable-ipv6 --enable-gre --enable-mpls --with-dnet-includes=/opt/libdnet111/include/ --with-dnet-libraries=/opt/libdnet111/lib/ --enable-targetbased --enable-decoder-preprocessor-rules --enable-ppm --enable-perfprofiling --enable-zlib --enable-active-response --enable-normalizer --enable-reload --enable-react --enable-flexresp3 LD_RUN_PATH="/opt/daq204/lib:/opt/snort2970/lib:/opt/libdnet111/lib:/usr/lib:/usr/local/lib" --prefix=/opt/snort2970/ --with-daq-includes=/opt/daq204/include/ --with-daq-libraries=/opt/daq204/lib/ && make -j ${processes} && sudo make install
sudo cp etc/* /opt/snort2970/etc/
cd ../../../

tar -xzvf engine-sources/snort/snort-2.9.7.2.tar.gz -C engine-sources/snort
cd engine-sources/snort/snort-2.9.7.2
PATH="/opt/daq204/bin:$PATH" ./configure --enable-ipv6 --enable-gre --enable-mpls --with-dnet-includes=/opt/libdnet111/include/ --with-dnet-libraries=/opt/libdnet111/lib/ --enable-targetbased --enable-decoder-preprocessor-rules --enable-ppm --enable-perfprofiling --enable-zlib --enable-active-response --enable-normalizer --enable-reload --enable-react --enable-flexresp3 LD_RUN_PATH="/opt/daq204/lib:/opt/snort2972/lib:/opt/libdnet111/lib:/usr/lib:/usr/local/lib" --prefix=/opt/snort2972/ --with-daq-includes=/opt/daq204/include/ --with-daq-libraries=/opt/daq204/lib/ && make -j ${processes} && sudo make install
sudo cp etc/* /opt/snort2972/etc/
cd ../../../

tar -xzvf engine-sources/daq/daq-2.0.5.tar.gz -C engine-sources/daq
cd engine-sources/daq/daq-2.0.5
./configure --prefix=/opt/daq205/ --with-dnet-includes=/opt/libdnet111/include/ --with-dnet-libraries=/opt/libdnet111/lib/ && make && sudo make install
cd ../../../

tar -xzvf engine-sources/snort/snort-2.9.7.3.tar.gz -C engine-sources/snort
cd engine-sources/snort/snort-2.9.7.3
PATH="/opt/daq205/bin:$PATH" ./configure --enable-ipv6 --enable-gre --enable-mpls --with-dnet-includes=/opt/libdnet111/include/ --with-dnet-libraries=/opt/libdnet111/lib/ --enable-targetbased --enable-decoder-preprocessor-rules --enable-ppm --enable-perfprofiling --enable-zlib --enable-active-response --enable-normalizer --enable-reload --enable-react --enable-flexresp3 LD_RUN_PATH="/opt/daq205/lib:/opt/snort2973/lib:/opt/libdnet111/lib:/usr/lib:/usr/local/lib" --prefix=/opt/snort2973/ --with-daq-includes=/opt/daq205/include/ --with-daq-libraries=/opt/daq205/lib/ && make -j ${processes} && sudo make install
sudo cp etc/* /opt/snort2973/etc/
cd ../../../

tar -xzvf engine-sources/daq/daq-2.0.6.tar.gz -C engine-sources/daq
cd engine-sources/daq/daq-2.0.6
./configure --prefix=/opt/daq206/ --with-dnet-includes=/opt/libdnet111/include/ --with-dnet-libraries=/opt/libdnet111/lib/ && make && sudo make install
cd ../../../

tar -xzvf engine-sources/snort/snort-2.9.7.5.tar.gz -C engine-sources/snort
cd engine-sources/snort/snort-2.9.7.5
PATH="/opt/daq206/bin:$PATH" ./configure --enable-ipv6 --enable-gre --enable-mpls --with-dnet-includes=/opt/libdnet111/include/ --with-dnet-libraries=/opt/libdnet111/lib/ --enable-targetbased --enable-decoder-preprocessor-rules --enable-ppm --enable-perfprofiling --enable-zlib --enable-active-response --enable-normalizer --enable-reload --enable-react --enable-flexresp3 LD_RUN_PATH="/opt/daq206/lib:/opt/snort2975/lib:/opt/libdnet111/lib:/usr/lib:/usr/local/lib" --prefix=/opt/snort2975/ --with-daq-includes=/opt/daq206/include/ --with-daq-libraries=/opt/daq206/lib/ && make -j ${processes} && sudo make install
sudo cp etc/* /opt/snort2975/etc/
cd ../../../

tar -xzvf engine-sources/snort/snort-2.9.7.6.tar.gz -C engine-sources/snort
cd engine-sources/snort/snort-2.9.7.6
PATH="/opt/daq206/bin:$PATH" ./configure --enable-ipv6 --enable-gre --enable-mpls --with-dnet-includes=/opt/libdnet111/include/ --with-dnet-libraries=/opt/libdnet111/lib/ --enable-targetbased --enable-decoder-preprocessor-rules --enable-ppm --enable-perfprofiling --enable-zlib --enable-active-response --enable-normalizer --enable-reload --enable-react --enable-flexresp3 LD_RUN_PATH="/opt/daq206/lib:/opt/snort2976/lib:/opt/libdnet111/lib:/usr/lib:/usr/local/lib" --prefix=/opt/snort2976/ --with-daq-includes=/opt/daq206/include/ --with-daq-libraries=/opt/daq206/lib/ && make -j ${processes} && sudo make install
sudo cp etc/* /opt/snort2976/etc/
cd ../../../

tar -xzvf engine-sources/snort/snort-2.9.8.0.tar.gz -C engine-sources/snort
cd engine-sources/snort/snort-2.9.8.0
PATH="/opt/daq206/bin:$PATH" ./configure --enable-ipv6 --enable-gre --enable-mpls --with-dnet-includes=/opt/libdnet111/include/ --with-dnet-libraries=/opt/libdnet111/lib/ --enable-targetbased --enable-decoder-preprocessor-rules --enable-ppm --enable-perfprofiling --enable-zlib --enable-active-response --enable-normalizer --enable-reload --enable-react --enable-flexresp3 LD_RUN_PATH="/opt/daq206/lib:/opt/snort2980/lib:/opt/libdnet111/lib:/usr/lib:/usr/local/lib" --prefix=/opt/snort2980/ --with-daq-includes=/opt/daq206/include/ --with-daq-libraries=/opt/daq206/lib/ && make -j ${processes} && sudo make install
sudo cp etc/* /opt/snort2980/etc/
cd ../../../

tar -xzvf engine-sources/snort/snort-2.9.8.2.tar.gz -C engine-sources/snort
cd engine-sources/snort/snort-2.9.8.2
PATH="/opt/daq206/bin:$PATH" ./configure --enable-ipv6 --enable-gre --enable-mpls --with-dnet-includes=/opt/libdnet111/include/ --with-dnet-libraries=/opt/libdnet111/lib/ --enable-targetbased --enable-decoder-preprocessor-rules --enable-ppm --enable-perfprofiling --enable-zlib --enable-active-response --enable-normalizer --enable-reload --enable-react --enable-flexresp3 LD_RUN_PATH="/opt/daq206/lib:/opt/snort2982/lib:/opt/libdnet111/lib:/usr/lib:/usr/local/lib" --prefix=/opt/snort2982/ --with-daq-includes=/opt/daq206/include/ --with-daq-libraries=/opt/daq206/lib/ && make -j ${processes} && sudo make install
sudo cp etc/* /opt/snort2982/etc/
cd ../../../

tar -xzvf engine-sources/snort/snort-2.9.8.3.tar.gz -C engine-sources/snort
cd engine-sources/snort/snort-2.9.8.3
PATH="/opt/daq206/bin:$PATH" ./configure --enable-ipv6 --enable-gre --enable-mpls --with-dnet-includes=/opt/libdnet111/include/ --with-dnet-libraries=/opt/libdnet111/lib/ --enable-targetbased --enable-decoder-preprocessor-rules --enable-ppm --enable-perfprofiling --enable-zlib --enable-active-response --enable-normalizer --enable-reload --enable-react --enable-flexresp3 LD_RUN_PATH="/opt/daq206/lib:/opt/snort2983/lib:/opt/libdnet111/lib:/usr/lib:/usr/local/lib" --prefix=/opt/snort2983/ --with-daq-includes=/opt/daq206/include/ --with-daq-libraries=/opt/daq206/lib/ && make -j ${processes} && sudo make install
sudo cp etc/* /opt/snort2983/etc/
cd ../../../

tar -xzvf engine-sources/snort/snort-2.9.9.0.tar.gz -C engine-sources/snort
cd engine-sources/snort/snort-2.9.9.0
PATH="/opt/daq206/bin:$PATH" ./configure --enable-ipv6 --enable-gre --enable-mpls --with-dnet-includes=/opt/libdnet111/include/ --with-dnet-libraries=/opt/libdnet111/lib/ --enable-targetbased --enable-decoder-preprocessor-rules --enable-ppm --enable-perfprofiling --enable-zlib --enable-active-response --enable-normalizer --enable-reload --enable-react --enable-flexresp3 LD_RUN_PATH="/opt/daq206/lib:/opt/snort2990/lib:/opt/libdnet111/lib:/usr/lib:/usr/local/lib" --prefix=/opt/snort2990/ --with-daq-includes=/opt/daq206/include/ --with-daq-libraries=/opt/daq206/lib/ && make -j ${processes} && sudo make install
sudo cp etc/* /opt/snort2990/etc/
cd ../../../

tar -xzvf engine-sources/snort/snort-2.9.11.tar.gz -C engine-sources/snort
cd engine-sources/snort/snort-2.9.11
PATH="/opt/daq206/bin:$PATH" ./configure --enable-ipv6 --enable-gre --enable-mpls --with-dnet-includes=/opt/libdnet111/include/ --with-dnet-libraries=/opt/libdnet111/lib/ --enable-targetbased --enable-decoder-preprocessor-rules --enable-ppm --enable-perfprofiling --enable-zlib --enable-active-response --enable-normalizer --enable-reload --enable-react --enable-flexresp3 LD_RUN_PATH="/opt/daq206/lib:/opt/snort2911/lib:/opt/libdnet111/lib:/usr/lib:/usr/local/lib" --prefix=/opt/snort2911/ --with-daq-includes=/opt/daq206/include/ --with-daq-libraries=/opt/daq206/lib/ && make -j ${processes} && sudo make install
sudo cp etc/* /opt/snort2911/etc/
cd ../../../

tar -xzvf engine-sources/snort/snort-2.9.11.1.tar.gz -C engine-sources/snort
cd engine-sources/snort/snort-2.9.11.1
PATH="/opt/daq206/bin:$PATH" ./configure --enable-ipv6 --enable-gre --enable-mpls --with-dnet-includes=/opt/libdnet111/include/ --with-dnet-libraries=/opt/libdnet111/lib/ --enable-targetbased --enable-decoder-preprocessor-rules --enable-ppm --enable-perfprofiling --enable-zlib --enable-active-response --enable-normalizer --enable-reload --enable-react --enable-flexresp3 LD_RUN_PATH="/opt/daq206/lib:/opt/snort29111/lib:/opt/libdnet111/lib:/usr/lib:/usr/local/lib" --prefix=/opt/snort29111/ --with-daq-includes=/opt/daq206/include/ --with-daq-libraries=/opt/daq206/lib/ && make -j ${processes} && sudo make install
sudo cp etc/* /opt/snort29111/etc/
cd ../../../

tar -xzvf engine-sources/snort/snort-2.9.12.tar.gz -C engine-sources/snort
cd engine-sources/snort/snort-2.9.12
PATH="/opt/daq206/bin:$PATH" ./configure --enable-ipv6 --enable-gre --enable-mpls --with-dnet-includes=/opt/libdnet111/include/ --with-dnet-libraries=/opt/libdnet111/lib/ --enable-targetbased --enable-decoder-preprocessor-rules --enable-ppm --enable-perfprofiling --enable-zlib --enable-active-response --enable-normalizer --enable-reload --enable-react --enable-flexresp3 LD_RUN_PATH="/opt/daq206/lib:/opt/snort2912/lib:/opt/libdnet111/lib:/usr/lib:/usr/local/lib" --prefix=/opt/snort2912/ --with-daq-includes=/opt/daq206/include/ --with-daq-libraries=/opt/daq206/lib/ && make -j ${processes} && sudo make install
sudo cp etc/* /opt/snort2912/etc/
cd ../../../


echo "Done installing engines"

#sudo python gunstar-maker.py

if [ -n "${oinkcode}" ]; then
  /usr/bin/python gunstar-maker.py -o ${oinkcode}
else
  /usr/bin/python gunstar-maker.py
fi

tar -xzvf engine-sources/misc/pulledpork-0.6.1.tar.gz -C engine-sources/misc
cd engine-sources/misc/pulledpork-0.6.1
patch -p1 < ../../../ppconfigs/pulledpork-etpro-fix.diff
sudo cp -f pulledpork.pl /usr/local/bin/
cd ../../../

sudo chmod 755 ruleupdates.sh
sudo mv ruleupdates.sh /usr/local/bin/
sudo cp enable-all-rules.py /usr/local/bin/
#sudo cp suricata-ld.conf /etc/ld.so.confd 
#sudo ldconfig -f /etc/ld.so.conf
sudo ldconfig
CURRENT_USER=`whoami`
sudo chown $CURRENT_USER /opt/snort* -Rf
sudo chown $CURRENT_USER /opt/suricata* -Rf
sudo chown $CURRENT_USER /opt/et-lua* -Rf

rm engine-sources/daq/daq-0.6.2 -Rf
rm engine-sources/daq/daq-0.5 -Rf
rm engine-sources/daq/daq-1.1.1 -Rf
rm engine-sources/daq/daq-2.0.0 -Rf
rm engine-sources/daq/daq-2.0.1 -Rf
rm engine-sources/daq/daq-2.0.2 -Rf
rm engine-sources/daq/daq-2.0.4 -Rf
rm engine-sources/daq/daq-2.0.5 -Rf
rm engine-sources/daq/daq-2.0.6 -Rf
rm engine-sources/snort/snort-2.9.0.4 -Rf
rm engine-sources/snort/snort-2.9.0.5 -Rf 
rm engine-sources/snort/snort-2.9.2.2 -Rf
rm engine-sources/snort/snort-2.9.2.3 -Rf
rm engine-sources/snort/snort-2.9.3 -Rf
rm engine-sources/snort/snort-2.9.3.1 -Rf
rm engine-sources/snort/snort-2.9.4.1 -Rf
rm engine-sources/snort/snort-2.9.4.6 -Rf
rm engine-sources/snort/snort-2.9.5.6 -Rf
rm engine-sources/snort/snort-2.9.6.0 -Rf
rm engine-sources/snort/snort-2.9.6.1 -Rf
rm engine-sources/snort/snort-2.9.6.2 -Rf
rm engine-sources/snort/snort-2.9.7.0 -Rf
rm engine-sources/snort/snort-2.9.7.2 -Rf
rm engine-sources/snort/snort-2.9.7.3 -Rf
rm engine-sources/snort/snort-2.9.7.5 -Rf
rm engine-sources/snort/snort-2.9.7.6 -Rf
rm engine-sources/snort/snort-2.9.8.0 -Rf
rm engine-sources/snort/snort-2.9.8.2 -Rf
rm engine-sources/snort/snort-2.9.8.3 -Rf
rm engine-sources/snort/snort-2.9.9.0 -Rf
rm engine-sources/snort/snort-2.9.11 -Rf
rm engine-sources/snort/snort-2.9.11.1 -Rf
rm engine-sources/snort/snort-2.9.12 -Rf

rm engine-sources/suricata/suricata-4.0.0 -Rf
rm engine-sources/suricata/suricata-4.0.1 -Rf
rm engine-sources/suricata/suricata-4.0.2 -Rf
rm engine-sources/suricata/suricata-4.0.3 -Rf
rm engine-sources/suricata/suricata-4.0.4 -Rf
rm engine-sources/suricata/suricata-4.0.5 -Rf
rm engine-sources/suricata/suricata-4.1.0 -Rf
rm engine-sources/suricata/suricata-5.0.3 -Rf
rm engine-sources/suricata/suricata-6.0.0 -Rf

rm engine-sources/misc/pulledpork-0.6.1 -Rf
rm engine-sources/misc/libdnet-1.11 -Rf
rm engine-sources/misc/lua-zlib -Rf
rm engine-sources/misc/luazip-1.2.4-1 -Rf
rm engine-sources/misc/ltn12ce -Rf
# start mysql (if not started)
#/etc/init.d/mysql restart 

#Update all rulesets
/usr/local/bin/ruleupdates.sh
echo -e "Done updating all rulesets for all engines\n"

