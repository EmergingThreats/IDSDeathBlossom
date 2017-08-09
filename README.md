# IDSDeathBlossom

This started off as a really small python script to automate some simple
tests. Now it is a bigger script that automates some simple tests :).  We
thought it might be useful to others so we open sourced it. It is licensed as
BSD except for code found under the `setup` directory.

Items in that directory have their own licenses.

## Run/Setup

First time install:

Run (as root)

```
./idsdb_install_dependencies.sh
./idsdb_install_all_engines.sh -o 1234567890
```
**NOTE:** All engines installation could take quite a while depending on the machine you have.

The example above will use oinkcode 1234567890 for the ruleset download and update/set up of all engines (Suricata and Snort)
If you dont have an oinkcode/etprocode - you can skip that option and the script will use ETOpen rulesets.

```
cp config/example-config.yaml config/config.yaml
```
Edit and set up your IDSDB config with any specififc passwords and IPs with regards to SQL DB and Moloch(if you are using it).

That's it!

How to test example (directory location and command dirs are important):

```
root@ET:~/IDSDeathBlossom# python IDSDeathBlossom.py -c config/config.yaml -R run -t "suricata-4.0.0-etopen-all" --reporton="TopNWorstAll,TopNWorstCurrent,LoadReportCurrent" --pcappath="pcaps/PDF-in-XPD-Safe-Example.pcap"
```
## Available optins

- Example IDSDB config is located under *IDSDeathBlossom/config/example-config.yaml*

- one command install and set up all available engines

- ability to add (or reinstall) a single engine (Suricata-xxxx/Suricata git/ Snort-xxxx).Thus making it much easier to keep in pace and have the latest engines available without having to update the whole IDSDB.

- all build scripts autodetect number of CPUs and use that number for compilation "make -j "

- sricata 2.x/3.x/4.x and git have et-luajit scripts in the rules directory ready to use

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

### example of how to run a test with Suricata 4.0.0 and etpro enabled all rules

`(etproenall,etopenenall)` - purposefully uncomment/enable all rules:

```
python IDSDeathBlossom.py -c config/config.yaml -R run -t "suricata-4.0.0-etproenall-all" --reporton="TopNWorstAll,TopNWorstCurrent,LoadReportCurrent" --pcappath="pcaps/PDF-in-XPD-Safe-Example.pcap"
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
