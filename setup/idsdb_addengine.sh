#!/bin/bash

# enable below if needed for troubleshooting
#set -e 

processes=$(getconf _NPROCESSORS_ONLN)

usage()
{
cat << EOF

usage: $0 [ OPTIONS ]

##############################
## IDSDB add engine options ##
##############################

Adds an engine (Suricata/Snort/Suricata latest git) to the IDSDB
with all necessary templates/rulesets and set up needed.

OPTIONS:
   -h      Help info
   -e      engine options - can be "suricata" or "snort"
   -o      Oinkcode to use (if desired) for ETPro ruleset. If not provided ETOpen will be used.
   -d      daq version for the snort engine
   -v      engine version (3.1/2.9.8.3)
           
   
   EXAMPLES: 
   ./idsdb_addengine.sh -e suricata -v 3.1.2
   The example above will add suricata 3.1.2 
   
   ./idsdb_addengine.sh -e suricata -v 3.1.2 -o 1234567890
   The example above will add suricata 3.1.2 and use oinkcode 1234567890 for ETPro ruleset set up.
   
   ./idsdb_addengine.sh -e snort -v 2.9.8.3 -d daq-2.0.6
   The example above will add snort 2.9.8.3 with daq-2.0.6. 
   Always make sure you have the right pair of versions of snort/daq.
   
   ./idsdb_addengine.sh -e snort -v 2.9.8.3 -d daq-2.0.6 -o 1234567890
   The example above will add snort 2.9.8.3 with daq-2.0.6. and use oinkcode 1234567890 for ETPro ruleset set up.
   Always make sure you have the right pair of versions of snort/daq
   
   ./idsdb_addengine.sh -e suricata -v git
   This example above will add latest suricata git (dev) edition. 

   ./idsdb_addengine.sh -e suricata -v git -o 1234567890
   This example above will add latest suricata git (dev) edition and use oinkcode 1234567890 for ETPro ruleset set up. 
   
   
EOF
}

# if no arguments supplied
if [ "$#" -eq 0 ]; then
  echo ""$0" needs arguments."
  usage
  exit 1
fi

while getopts “he:o:d:v:” OPTION
do
     case $OPTION in
         h)
             usage
             exit 1
             ;;
         e)
             engine_type=$OPTARG
             if ! [[ "${engine_type}" =~ ^(snort|suricata)$ ]];
             then
               echo "Please use - snort OR suricata engine"
               echo -e "\n EXMPLE:"
               echo -e "./idsdb_addengine.sh -e snort -v 2.9.8.3 -d daq-2.0.6"
               echo -e "./idsdb_addengine.sh -e suricata -v 3.1.2\n"
               exit 1;
             fi
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
         d)
             daq_version=$OPTARG 
             echo "daq version to be used with snort - ${daq_version} "
             ;;
         v)
             engine_version=$OPTARG
             if ! [[ "${engine_version}" =~ ^[1-9]\.[0-9]+?\.?[0-9]+?\.?[0-9]+$ ]]; 
             then
               if ! [[ "${engine_version}" == "git" ]];
               then
                 echo -e "\n Please supply a correct version form \n"
                 usage
                 exit 1;
               fi
             fi
             ;;
         *)
             engine_type=
             engine_version=
             daq_version=
             oinkcode=
             echo "Not expected options supplied "
             exit 1;
             ;;

     esac
done
shift $((OPTIND -1))

echo -e "\n Supplied engine and version are:  ${engine_type} ${engine_version}  \n";
#echo "${engine_type}-${engine_version}"

  if [ "${engine_type}" == "snort" ] && [ -z  "${engine_version}" ]; then
      echo -e "\n USAGE: `basename $0` the script requires three arguments for the Snort engine."
      echo -e "\n EXMPLE:"
      echo -e "\n ./idsdb_addengine.sh -e snort -v 2.9.8.3 -d daq-2.0.6"
      exit 1;
  fi

  if [ "${engine_type}" == "suricata" ] && [ -z  "${engine_version}" ]; then 
      echo -e "\n USAGE: `basename $0` the script requires two arguments for the Suricata engine."
      echo -e "\n EXMPLE:"
      echo -e "\n ./idsdb_addengine.sh -e suricata -v 3.1.2"
      echo -e "\n ./idsdb_addengine.sh -e suricata -v git"
      exit 1;
  fi
  

if [ "${engine_type}" == "snort" ] &&  [ -z  "${daq_version}" ] ; then
  echo -e "\n Please supply DAQ version for Snort"
  echo -e "\n ./idsdb_addengine.sh -e snort -v 2.9.8.3 -d daq-2.0.6"
  exit 1
fi 

echo "http://www.openinfosecfoundation.org/download/${engine_type}-${engine_version}.tar.gz"

if [ "${engine_type}" == "suricata" ] && [  "${engine_version}" == "git" ]; then

    if [  -d "engine-sources/${engine_type}/${engine_type}-${engine_version}" ]; then
    rm -rf engine-sources/${engine_type}/${engine_type}-${engine_version}
    fi

    if   $(git clone git://phalanx.openinfosecfoundation.org/oisf.git engine-sources/${engine_type}/${engine_type}-${engine_version} && cd engine-sources/${engine_type}/${engine_type}-${engine_version} && git clone https://github.com/OISF/libhtp.git -b 0.5.x && cd ../../../)  ; then
    echo "Downloaded the latest Suricata version."
    else
    echo "Could not download! Aborting. Check your connection or engine version and try again." 
    echo "git clone git://phalanx.openinfosecfoundation.org/oisf.git or git clone https://github.com/OISF/libhtp.git -b 0.5.x" 1>&2
    exit 1
    fi

    # ${engine_type}-${engine_version} - suricata-git
    # ${engine_name} - suricatagit
    engine_name=$(echo ${engine_type}${engine_version})
    echo "sudo mkdir -p /opt/${engine_name}/{bin,lib,include/linux,sbin,etc/etpro,etc/etproenall,etc/etopen,etc/etopenenall,/etc/test,var/run/suricata,var/log,etc/sanitize/sopen,etc/sanitize/spro}"
    sudo mkdir -p /opt/${engine_name}/{bin,lib,include/linux,sbin,etc/etpro,etc/etproenall,etc/etopen,etc/etopenenall,/etc/test,var/run/suricata,var/log,etc/sanitize/sopen,etc/sanitize/spro}
    
    cd engine-sources/${engine_type}/${engine_type}-${engine_version}
    
    ./autogen.sh && ./configure --enable-lua --enable-profiling --prefix=/opt/${engine_name}/ \
    --with-libnss-includes=/usr/include/nss --with-libnss-libs=/usr/lib/nss \
    --with-libnspr-includes=/usr/include/nspr --with-libnspr-libraries=/usr/lib/nspr && \
    make -j ${processes} && sudo make install && sudo ldconfig
    
    sudo cp suricata.yaml /opt/${engine_name}/etc/
    sudo cp ../../../engine-configs/suricata/reference.config /opt/${engine_name}/etc/
    sudo cp ../../../engine-configs/suricata/classification.config /opt/${engine_name}/etc/
    sudo cp ../../../engine-configs/suricata/threshold.config /opt/${engine_name}/etc/
    cd ../../../
    
    # use latest version of the templates
    cp engine-templates/base-suricata4.template engine-templates/${engine_name}.template
    #default-log-dir: /opt/suricatagit/var/log/
    #classification-file: /opt/suricatagit/etc/classification.config
    #reference-config-file: /opt/suricatagit/etc/reference.config
    #threshold-file: /opt/suricatagit/etc/threshold.config
    sed -i '/rule-files:/d' engine-templates/${engine_name}.template
    echo "default-log-dir: /opt/${engine_name}/var/log/" >> engine-templates/${engine_name}.template
    echo "classification-file: /opt/${engine_name}/etc/classification.config" >> engine-templates/${engine_name}.template
    echo "reference-config-file: /opt/${engine_name}/etc/reference.config" >> engine-templates/${engine_name}.template
    echo "threshold-file: /opt/${engine_name}/etc/threshold.config" >> engine-templates/${engine_name}.template
    echo "rule-files:" >> engine-templates/${engine_name}.template
    rm -rf engine-sources/${engine_type}/${engine_type}-${engine_version}
    
    # we need a doted version for gunstar
    # gunstar_engine_version=$(/opt/${engine_name}/bin/suricata -V | awk '{print $5}' |cut -c1-3)
    # /usr/bin/python test-gunstar-maker.py ${engine_type} ${gunstar_engine_version}
    if [ -n "${oinkcode}" ]; then
      /usr/bin/python gunstar-maker.py -e ${engine_type} -v ${engine_version} -o ${oinkcode}
    else
      /usr/bin/python gunstar-maker.py -e ${engine_type} -v ${engine_version}
    fi
    [[ $? -eq "0" ]] && echo "successfully added engine template" || exit 1
   
  
fi


if  [ "${engine_type}" == "suricata" ] && [  "${engine_version}" != "git" ]; then

  if [ ! -f "engine-sources/${engine_type}/${engine_type}-${engine_version}.tar.gz" ]; then
    if   $(wget -P engine-sources/${engine_type}/ https://www.openinfosecfoundation.org/download/${engine_type}-${engine_version}.tar.gz)  ; then
      echo "Downloaded Suricata."
    else
      echo "Could not download! Aborting. Check your connection or engine version and try again." 
      echo "https://www.openinfosecfoundation.org/download/${engine_type}-${engine_version}.tar.gz" 1>&2
      exit 1
    fi
  fi

  # ${engine_type}-${engine_version} - suricata-3.1.2
  # ${engine_name} - suricata312
  engine_name=$(echo ${engine_type}${engine_version//./})
  echo "sudo mkdir -p /opt/${engine_name}/{bin,lib,include/linux,sbin,etc/etpro,etc/etproenall,etc/etopen,etc/etopenenall,/etc/test,var/run/suricata,var/log,etc/sanitize/sopen,etc/sanitize/spro}"
  sudo mkdir -p /opt/${engine_name}/{bin,lib,include/linux,sbin,etc/etpro,etc/etproenall,etc/etopen,etc/etopenenall,/etc/test,var/run/suricata,var/log,etc/sanitize/sopen,etc/sanitize/spro}
  
  tar -xzvf engine-sources/${engine_type}/${engine_type}-${engine_version}.tar.gz -C engine-sources/${engine_type}
  cd engine-sources/${engine_type}/${engine_type}-${engine_version}
  ./configure --enable-lua --enable-profiling --prefix=/opt/${engine_name}/ --with-libnss-includes=/usr/include/nss --with-libnss-libs=/usr/lib/nss --with-libnspr-includes=/usr/include/nspr --with-libnspr-libraries=/usr/lib/nspr && make -j ${processes} && sudo make install && sudo ldconfig
  sudo cp suricata.yaml /opt/${engine_name}/etc/
  sudo cp ../../../engine-configs/suricata/reference.config /opt/${engine_name}/etc/
  sudo cp ../../../engine-configs/suricata/classification.config /opt/${engine_name}/etc/
  sudo cp ../../../engine-configs/suricata/threshold.config /opt/${engine_name}/etc/
  cd ../../../
  
  if [[ ${engine_name} = *"suricata40"* ]]; then
    cp engine-templates/base-suricata4.template engine-templates/${engine_name}.template
  else
    cp engine-templates/base-suricata.template engine-templates/${engine_name}.template
  fi
  
  #default-log-dir: /opt/suricata311/var/log/
  #classification-file: /opt/suricata311/etc/classification.config
  #reference-config-file: /opt/suricata311/etc/reference.config
  #threshold-file: /opt/suricata311/etc/threshold.config
  sed -i '/rule-files:/d' engine-templates/${engine_name}.template
  echo "default-log-dir: /opt/${engine_name}/var/log/" >> engine-templates/${engine_name}.template
  echo "classification-file: /opt/${engine_name}/etc/classification.config" >> engine-templates/${engine_name}.template
  echo "reference-config-file: /opt/${engine_name}/etc/reference.config" >> engine-templates/${engine_name}.template
  echo "threshold-file: /opt/${engine_name}/etc/threshold.config" >> engine-templates/${engine_name}.template
  echo "rule-files:" >> engine-templates/${engine_name}.template
  rm engine-sources/${engine_type}/${engine_type}-${engine_version} -r
  
  if [ -n "${oinkcode}" ]; then
    /usr/bin/python gunstar-maker.py -e ${engine_type} -v ${engine_version} -o ${oinkcode}
  else
    /usr/bin/python gunstar-maker.py -e ${engine_type} -v ${engine_version}
  fi
  [[ $? -eq "0" ]] && echo "successfully added engine template" || exit 1
   
  
fi


if [ "${engine_type}" == "snort" ] &&  [ "${daq_version}" ]; then
  # ${daq_version} - daq-2.0.6
  # ${daq_name} - daq206
  daq_name=$(echo ${daq_version//./})
  daq_name=$(echo ${daq_name//-/})
  
  if [ ! -f "engine-sources/${engine_type}/${engine_type}-${engine_version}.tar.gz" ]; then
    if   $(wget -P engine-sources/${engine_type}/ https://www.snort.org/downloads/snort/${engine_type}-${engine_version}.tar.gz)  ; then
      echo "Downloaded https://www.snort.org/downloads/snort/${engine_type}-${engine_version}.tar.gz"
    else
      echo "Could not download! Aborting. Check your connection or spelling/version and try again." 
      echo "https://www.snort.org/downloads/snort/${engine_type}-${engine_version}.tar.gz" 1>&2
      exit 1
    fi
  fi

  if [ ! -f "engine-sources/daq/${daq_version}.tar.gz" ]; then
    if  $(wget -P engine-sources/daq/ https://www.snort.org/downloads/snort/${daq_version}.tar.gz)  ; then
      echo "Downloaded DAQ - https://www.snort.org/downloads/snort/${daq_version}.tar.gz"
    else 
      echo "Could not download or find it! Aborting. Check your connection or spelling/version and try again." 
      echo "https://www.snort.org/downloads/snort/${engine_type}-${engine_version}.tar.gz" 1>&2
      exit 1
    fi
  fi

  # ${engine_type}-${engine_version} - snort-2.9.8.3
  # ${engine_name} - snort2983
  engine_name=$(echo ${engine_type}${engine_version//./})
  echo "sudo mkdir -p /opt/${engine_name}/{bin,lib,include/linux,sbin,etc/etpro,etc/etproenall,etc/etopen,etc/etopenenall,/etc/test,var/run/suricata,var/log,etc/sanitize/sopen,etc/sanitize/spro}"
  sudo mkdir -p /opt/${engine_name}/{bin,lib,include/linux,sbin,etc/etpro,etc/etproenall,etc/etopen,etc/etopenenall,/etc/test,var/run/suricata,var/log,etc/sanitize/sopen,etc/sanitize/spro}
  
  tar -xzvf engine-sources/daq/${daq_version}.tar.gz -C engine-sources/daq/
  cd engine-sources/daq/${daq_version}
  ./configure --prefix=/opt/${daq_name}/ --with-dnet-includes=/opt/libdnet111/include/ --with-dnet-libraries=/opt/libdnet111/lib/ && make && sudo make install
  cd ../../../
  rm engine-sources/daq/${daq_version} -r
  
  tar -xzvf engine-sources/${engine_type}/${engine_type}-${engine_version}.tar.gz -C engine-sources/${engine_type}
  cd engine-sources/${engine_type}/${engine_type}-${engine_version}
  PATH="/opt/${daq_name}/bin:$PATH" ./configure --enable-ipv6 --enable-gre --enable-mpls --with-dnet-includes=/opt/libdnet111/include/ --with-dnet-libraries=/opt/libdnet111/lib/ --enable-targetbased --enable-decoder-preprocessor-rules --enable-ppm --enable-perfprofiling --enable-zlib --enable-active-response --enable-normalizer --enable-reload --enable-react --enable-flexresp3 LD_RUN_PATH="/opt/${daq_name}/lib:/opt/${engine_name}/lib:/opt/libdnet111/lib:/usr/lib:/usr/local/lib" --prefix=/opt/${engine_name}/ --with-daq-includes=/opt/${daq_name}/include/ --with-daq-libraries=/opt/${daq_name}/lib/ && make -j ${processes} && sudo make install && sudo ldconfig
  sudo cp etc/* /opt/${engine_name}/etc/
  cd ../../../
  rm engine-sources/${engine_type}/${engine_type}-${engine_version} -r
  
  cp engine-templates/base-${engine_type}.template engine-templates/${engine_name}.template
  echo "dynamicpreprocessor directory /opt/${engine_name}/lib/snort_dynamicpreprocessor/" >> engine-templates/${engine_name}.template
  echo "dynamicengine /opt/${engine_name}/lib/snort_dynamicengine/libsf_engine.so" >> engine-templates/${engine_name}.template
  sed -i -e "/preprocessor http_inspect_server: server default/i preprocessor http_inspect: global iis_unicode_map \/opt\/${engine_name}\/etc\/unicode.map 1252 compress_depth 65535 decompress_depth 65535"  engine-templates/${engine_name}.template
  echo "include /opt/${engine_name}/etc/classification.config" >> engine-templates/${engine_name}.template
  echo "include /opt/${engine_name}/etc/reference.config" >> engine-templates/${engine_name}.template
  
  if [ -n "${oinkcode}" ]; then
    /usr/bin/python gunstar-maker.py -e ${engine_type} -v ${engine_version} -o ${oinkcode}
  else
    /usr/bin/python gunstar-maker.py -e ${engine_type} -v ${engine_version}
  fi
  [[ $? -eq "0" ]] && echo "successfully added engine template" || exit 1
   
  
fi

