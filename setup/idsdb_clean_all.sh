#!/bin/sh

#./idsdb_clean_all.sh
# Cleans/removes all IDSDB installed engines 

sudo rm /opt/libdnet111 -Rf
#sudo rm /opt/luajit20 -Rf
#sudo rm /opt/pcre-8.3* -Rf
sudo rm /opt/snort* -Rf
sudo rm /opt/suricata* -Rf
sudo rm /opt/et-luajit-scripts -Rf
sudo rm /opt/daq* -Rf
sudo rm /usr/local/bin/ruleupdates.sh -Rf

