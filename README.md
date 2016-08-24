# IDSDeathBlossom

This started off as a really small python script to automate some simple
tests. Now it is a bigger script that automates some simple tests :).  We
thought it might be useful to others so we open sourced it. It is licensed as
BSD except for code found under the `setup` directory.

Items in that directory have their own licenses.

## Run/Setup

You need to execute the following steps below.

1. You need to download the new/wanted Suricata/Snort tar.gz ball version (for
example Suricata 2.0.7) - respective versions and put them in the
IDSDeathBlossom/setup directory

2. Create/Add the necessary dirs at the top of the setup/Ubuntu-12.04-LTS.sh
script (example for Suricata 2.0.7):

```
sudo mkdir -p /opt/suricata207/{bin,lib,include/linux,sbin,etc/etpro,etc/etopen,/etc/test,var/log,etc/sanitize/sopen,etc/sanitize/spro}
```

3. Add the following to the setup/Ubuntu-12.04-LTS.sh script (example for Suricata 2.0.7):

```
tar -xzvf suricata-2.0.7.tar.gz
cd suricata-2.0.7
./configure --enable-lua --enable-profiling --prefix=/opt/suricata207/ --with-libnss-includes=/usr/include/nss --with-libnss-libs=/usr/lib/nss --with-libnspr-includes=/usr/include/nspr --with-libnspr-libraries=/usr/lib/nspr && make -j && sudo make install
sudo cp suricata.yaml /opt/suricata207/etc/
sudo cp ../reference.config /opt/suricata207/etc/
sudo cp ../classification.config /opt/suricata207/etc/
sudo cp ../threshold.config /opt/suricata207/etc/
cd ..
```

At the bottom of the script add:

```
rm suricata-2.0.7 -Rf
```


4) Save and manually create templates in `setup/engine-templates/suricata207.template`.
You can copy from `204/203` versions for example
and then you need to change the following directories inside:

```
default-log-dir: /opt/suricata207/var/log/
classification-file: /opt/suricata207/etc/classification.config
reference-config-file: /opt/suricata207/etc/reference.config
threshold-file: /opt/suricata207/etc/threshold.config
```

5. In `/setup/gunstar-maker.py` just add the engines -

```
engines["suricata207"] = {"type":"suricata", "version":"2.0.7", "eversion":"2.0.7"}
```

6. Run the Ubuntu set up script:

```
root@ET:~/Work/ET/IDSDeathBlossom/setup# ./Ubuntu-12.04-LTS.sh
```

(If you do not have an ETPro code, do not enter anything when asked - just hit enter)

7. Set up the mysql DB (make sure the mysql server is started)

```
root@ET:~/Work/ET/IDSDeathBlossom/setup# mysql -u root -p < mysql_setup.sql
```

8. Run the ruleupdate script

```
root@ET:~/Work/ET/IDSDeathBlossom/setup# /usr/local/bin/ruleupdates.sh
```
9. Proceed with a test

How to test example (directory location and command dirs are important):

```
root@ET:~/IDSDeathBlossom# python IDSDeathBlossom.py -c config/config.yaml -R run -t "suricata-2.0.7-etopen-all" --reporton="TopNWorstAll,TopNWorstCurrent,LoadReportCurrent" --pcappath="pcaps/PDF-in-XPD-Safe-Example.pcap"
```

## Test/Examples

Please, feel free to add yours. (We should say which opts are mandatory and which ones can be loaded from config)

### Some reports

```
python -i IDSDeathBlossom.py -c config/config.yaml -R run -t "snort2861open" --emailsubject="generate sidperf" --pcappath=/pcaps/etqa/2003579.pcap --loopnum 5 --reporton="TopNWorstAll,TopNWorstCurrent,LoadReportCurrent"
```

### Sid perf

```
python -i IDSDeathBlossom.py -c config/config.yaml -R sidperfq -t "snort2861open" --emailsubject="query perf stats" --sperfsid 2010238
```

### compare

```
python -i IDSDeathBlossom.py -c config/config.yaml -R comparefast -t "snort2861open" --emailsubject="compare" --cmpropts="logs/snort-alert-2010-10-19-T-09-42-36-2010238.pcap.txt:tag1,logs/snort-alert-2010-10-19-T-09-42-40-2010238.pcap.txt:tag2"
```

### rcompare

```
python -i IDSDeathBlossom.py -c config/config.yaml -R rcomparefast -t "snort2861open,snort2841open" --emailsubject="rcompare" --cmpropts="logs/snort-alert-2010-10-19-T-09-42-36-2010238.pcap.txt:tag1,logs/snort-alert-2010-10-19-T-13-17-05-2010239.pcap.txt:tag2" --pcappath="/pcaps/etqa/2008438.pcap" --loopnum 2
```

### sanitize

```
python -i IDSDeathBlossom.py -c config/config.yaml -R sanitize -t "snort2861open,snort2841open" --emailsubject="sanitize"
```

### example of how to run a test with Suricata 2.0.8 and etpro enabled all rules

`(etproenall,etopenenall)` - purposefully uncomment/enable all rules:

```
python IDSDeathBlossom.py -c config/config.yaml -R run -t "suricata-2.0.8-etproenall-all" --reporton="TopNWorstAll,TopNWorstCurrent,LoadReportCurrent" --pcappath="pcaps/PDF-in-XPD-Safe-Example.pcap"
```

### Template usage example:

The templates are specified at the engine configurations/profiles available. custom rules can be also specified at config. You just need to set it (at config or cli) and use the flag  `--use-custom-rules`, that will generate a config for that rules

```
python IDSDeathBlossom.py -c config/config.yaml -t snort2861pro -R run --pcappath=/pcaps/etqa/2002192.pcap --use-custom-rules --target-opts="all:customrules=./lala"
```

###  some stats

```
python -i IDSDeathBlossom.py -c config/config.yaml -R run --pcappath=/pcaps/etqa/201114*  -t snort2861open,snort2861pro,snort2841open,snort2841pro,suricata102open,suricata102pro --reporton=idsperf,ruleperf --loopnum=1
```

### custom queries

```
python IDSDeathBlossom.py -c config/config.yaml --sqlquery="SELECT * from rulestats"|more
```

### verify

```
python -i IDSDeathBlossom.py -c config/config.yaml -R verify -t "snort2861open" --target-opts="snort2861open:configtpl=config/engines/snort2861.tpl.conf" --verifyconf="config/tests.yaml"
```

### dumbfuzz

```
python -i IDSDeathBlossom.py -c config/config.yaml -R dumbfuzz -t "snort2861open" --pcappath="/pcaps/ictf*/*.pcap,/pcaps/dc*/*" --loopnum forever
```

### Generate a topN report for a past run

```
IDSDeathBlossom.py -c config/config.yaml -R reportonly --custom-runid=Daily-Perf-Run-suricata-1.3-21-2012-08-29_01-04-44 --reporton=TopNWorstCurrent,LoadReportCurrent --topN=100
```
