# -*- coding: utf-8 -*-

#*************************************************************
#  Copyright (c) 2003-2012, Emerging Threats
#  All rights reserved.
#  
#  Redistribution and use in source and binary forms, with or without modification, are permitted provided that the 
#  following conditions are met:
#  
#  * Redistributions of source code must retain the above copyright notice, this list of conditions and the following 
#    disclaimer.
#  * Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the 
#    following disclaimer in the documentation and/or other materials provided with the distribution.
#  * Neither the name of the nor the names of its contributors may be used to endorse or promote products derived 
#    from this software without specific prior written permission.
#  
#  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS AS IS AND ANY EXPRESS OR IMPLIED WARRANTIES, 
#  INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE 
#  DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, 
#  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR 
#  SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, 
#  WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE 
#  USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE. 
#
#*************************************************************

import time
import yaml 
import glob
import socket, struct
from IDSUtils import *
from IDSMail import *
from IDSRunmodeSanitize import *
from IDSRunmodeExtract import *
from IDSRunmodeExtractAll import *
from IDSRunmodeVerify import *
from IDSRunmodeSidperfq import *
from IDSRunmodeCompare import *
from IDSRunmodeDumbFuzz import *
from IDSLogging import *

# Class for any type of engine
class IDSEngine(RunmodeSanitize, RunmodeExtract, RunmodeExtractAll, RunmodeVerify, RunmodeSidperfq, RunmodeCompare, RunmodeDumbFuzz):
    def __init__(self, engine):
        self.errcnt = 0
        self.warncnt = 0
        #p_debug("Loading conf vars of %s" % engine)
        self.conf = engine
        self.reports = {}

        self.mode = self.conf['type']
# {'engine': 'snort2861pro', 'enable': True, 'type': 'snort', 'fastlog': 'alert', 'summary': 'snort 2.8.6.1 with config of ET pro rules', 'version': '2.8.6.1', 'logdir': './logs/', 'path': '/opt/snort2861/bin/snort', 'config': '/opt/snort2861/etc/snort-et-pro.conf', 'configtpl': '/opt/snort2861/etc/snort.conf.tpl'}

        self.sidd = {}
        self.conf["version"] = str(self.conf["version"])
        # make sure version is always a string - not float or int
        #Default variables
        self.currentts = ""
        # Set defaults for each engine type if any field is missing
        self.regex = {}
        #Regex for matching on alert fast formated log files with GID of one. If somebody else wants to add support for .so rule etc go for it
        self.regex["afast"] = re.compile(r".+\[1\:(?P<sid>\d+)\:\d+\].+\{(?P<proto>UDP|TCP|ICMP|(PROTO\:)?\d+)\}\s(?P<src>\d+\.\d+\.\d+\.\d+)(:(?P<sport>\d+))?\s.+\s(?P<dst>\d+\.\d+\.\d+\.\d+)(:(?P<dport>\d+))?")
        self.regex["afast_full_parser"] = re.compile(r"^(?P<ts>[^\s]*)\s+?\[\*\*\]\s+?\[(?P<gid>\d+)\:(?P<sid>\d+)\:(?P<rev>\d+)\]\s+(?P<msg>.+?)\s+?\[\*\*\]\s+?(\[Classification\:\s+?(?P<class>[^\]]+)\]\s+?)?\[Priority\:\s+?(?P<prio>\d+?)\]\s+?{(?P<proto>UDP|TCP|ICMP|(PROTO\:)?\d+)\}\s(?P<src>\d+\.\d+\.\d+\.\d+)(:(?P<sport>\d+))?\s.+\s(?P<dst>\d+\.\d+\.\d+\.\d+)(:(?P<dport>\d+))?$")
        #Regex for matching on snort perf logs
        #self.regex["perf"] = re.compile(r"^\s+(?P<rank>\d+)\s+(?P<sid>\d+)\s+(?P<gid>1)\s+(?P<rev>\d+)?\s+(?P<checks>\d+)\s+(?P<matches>\d+)\s+(?P<alerts>\d+)\s+(?P<microsecs>\d+)\s+(?P<avgpercheck>\d+\.\d+)\s+(?P<avgpermatch>\d+\.\d+)\s+(?P<avgpernomatch>\d+\.\d+)\s+$")

        #perf log regex support for 2.9.0.1 Disabled column?!?!
        self.regex["perf"] = re.compile(r"^\s+?(?P<rank>\d+)\s+?(?P<sid>\d+)\s+?(?P<gid>1)\s+?(?P<rev>\d+)?\s+?(?P<checks>\d+)\s+?(?P<matches>\d+)\s+?(?P<alerts>\d+)\s+?(?P<microsecs>\d+)\s+?(?P<avgpercheck>\d+\.\d+)\s+?(?P<avgpermatch>\d+\.\d+)\s+?(?P<avgpernomatch>\d+\.\d+)\s+?((0|1)\s+?)?$")

        #Regex for matching error lines from suri and snort
        self.regex["error"] = re.compile(r"(^Error|^ERROR|.+\<Error\>|FATAL ERROR)", re.IGNORECASE)

        #Regex for matching warning lines from suri and snort
        self.regex["warning"] = re.compile(r"(^Warning|^WARNING|.+\<Warning\>)", re.IGNORECASE)

        #TODO: Add more error formats (there are some more)
        #Regex for parsing file and line of error/warning when loading sigs 
        #Warning: /opt/ruledump/snort-2.8.6/open/all.rules(2) => threshold (in rule) is deprecated; use detection_filter instead.
        #ERROR: /opt/ruledump/snort-2.8.6/open/all.rules(9004) Undefined variable name: HTTP_PORTS.
        #[13755] 22/9/2010 -- 18:54:11 - (detect.c:307) <Error> (DetectLoadSigFile) -- [ERRCODE: SC_ERR_INVALID_SIGNATURE(39)] - Error parsing signature "alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"ET POLICY AOL Toolbar User-Agent (AOLToolbar)"; flow:to_server,established; content:"AOLToolbar"; http_header; nocase; pcre:"/User-Agent\x3a[^\n]+AOLToolbar/Hi"; classtype:policy-violation; reference:url,doc.emergingthreats.net/bin/view/Main/2003469; reference:url,www.emergingthreats.net/cgi-bin/cvsweb.cgi/sigs/POLICY/POLICY_AOL_To" from file /opt/ruledump/suricata/open/all.rules at line 1496

        self.regex["rule_warn_snort"] = re.compile(r".*(Warning|WARNING|warning).*(\s|:)+(?P<file>(\/+[a-zA-Z0-9\-\_\.]+)+)\s*\((?P<line>\d+)\).*", re.IGNORECASE)
        self.regex["rule_err_snort"] = re.compile(r".*(Error|ERROR|error).*(\s|:)+(?P<file>(\/+[a-zA-Z0-9\-\_\.]+)+)\s*\((?P<line>\d+)\).*", re.IGNORECASE)


        self.regex["rule_warn_snort_multi_line"] = re.compile(r".*(Warning|WARNING|warning).*(\s|:)+\n(?P<file>(\/+[a-zA-Z0-9\-\_\.]+)+)\s*\((?P<line>\d+)\).*", re.IGNORECASE)
        self.regex["rule_err_snort_multi_line"] = re.compile(r".*(ERROR|Error|error).*(\s|:)+\n(?P<file>(\/+[a-zA-Z0-9\-\_\.]+)+)\s*\((?P<line>\d+)\).*", re.IGNORECASE)
        #self.regex["rule_warn_snort"] = re.compile(r"(Warning:|WARNING|warning).*(\s|:|\n)(?P<file>\/[^\s\(]+\.rules)\s*\((?P<line>\d+)\)", re.IGNORECASE)
        #self.regex["rule_err_snort"] = re.compile(r"(ERROR|Error|error).*(\s|:|\n)(?P<file>\/[^\s\(]+\.rules)\s*\((?P<line>\d+)\)", re.IGNORECASE)

        self.regex["rule_warn_suricata"] = re.compile(r"<Warning> .* from file (?P<file>[^\s]+) at line (?P<line>\d+)")
        self.regex["rule_err_suricata"] = re.compile(r".*<Error> \(DetectLoadSigFile\) -- \[ERRCODE: SC_ERR_INVALID_SIGNATURE\(\d+\)\] - Error parsing signature .* from file (?P<file>[^\s]+) at line (?P<line>\d+)\s*$")

        #Regex for checking if all rules where successfully loaded
        self.regex["all_rules_loaded"] = re.compile(r"(^Snort successfully loaded all rules and checked all rule chains| rules succesfully loaded, 0 rules failed\s*$)")


        #Regex for ignoring stupid errors and warnings.
        #TODO: Make this user configurable
        self.regex["ignore"]  = re.compile(r".+threshold \(in rule\) is deprecated\; use detection\_filter instead")

        #Regex for email addresses
        self.regex["email"] = re.compile(r"(?:^|\s)[-a-z0-9_.]+@(?:[-a-z0-9]+\.)+[a-z]{2,6}(?:\s|$)",re.IGNORECASE)
        
        #Regex for file compare options in format file1:mode1,file2:mode2
        self.regex["cmpropts"] = re.compile(r"^(?P<file1>.+)\:(?P<mode1>.+)\,(?P<file2>.+)\:(?P<mode2>.+)$")

        self.warnings = []
        self.errors = []

    def setDefaults(self):
        self.engine = self.conf['engine']
        self.path = self.conf['path']
        self.config = self.conf['config']
        self.configtpl = self.conf['configtpl']
        self.logdir = self.conf['logdir']
        self.fastlog = self.conf['fastlog']
        self.logfile = "%s/%s" % (self.conf['logdir'], self.conf['fastlog'])


        if self.Runmode.conf.has_key("usecustomrules") and self.Runmode.conf["usecustomrules"]:
            self.useTemplateConfig()

        if self.conf.has_key("perflog"):
            self.perflog = self.conf['perflog']
        else:
            self.perflog = "default-perflog"
        self.perflogfile = "%s/%s" % (self.conf['logdir'], self.perflog)

        if self.Runmode.conf.has_key("runid"):
            self.runid = self.Runmode.conf["runid"]
        else:
            self.runid = None
        if self.Runmode.conf.has_key("reportonsanitize"):
            self.reportonsanitize = self.Runmode.conf["reportonsanitize"]
        else:
            self.reportonsanitize = 1

    def __str__(self):
        s = ""
        for v in self.conf.keys():
            s = "%s%s = %s\n" % (s, v, self.conf[v])
        #return str(self.conf)
        return s

    def useTemplateConfig(self):
            #parse the snort config    
            try:
                self.config = generate_config(self.conf["type"], self.conf["customrules"], self.conf["configtpl"])
                self.conf["config"] = self.config
            except:
                p_error("%s: Problems generating the config template. Review the vars 'customrules' and 'configtpl'" % str(whoami()))
                sys.exit(1)

    def getCmd(self, runmode, pcap=None):
        cmd = ""
        # sanitization has -T and --init-errors as special opts
        if runmode == "sanitize":
            if self.mode == "snort":
                if  self.conf["version"] == "2.4.5":
                    cmd = "%s -c %s -K none -l %s -T -i eth0" % (self.conf["path"], self.conf["config"], self.conf["logdir"])
                elif re.match(r"^2\.9\.",self.conf["version"]) != None:
                    cmd = "%s -c %s -K none -l %s -T --daq pcap" % (self.conf["path"], self.conf["config"], self.conf["logdir"])
                else:
                    cmd = "%s -c %s -K none -l %s -T" % (self.conf["path"], self.conf["config"], self.conf["logdir"])
            elif self.mode == "suricata":
                #if re.match(r"^2\.",self.conf["version"]) != None:
                #    cmd = "%s -c %s -l %s -r %s --init-errors -v" % (self.conf["path"], self.conf["config"], self.conf["logdir"], self.pcapfile)
                #else:
                #    cmd = "%s -c %s -l %s -r %s --init-errors" % (self.conf["path"], self.conf["config"], self.conf["logdir"], self.pcapfile)
                if re.match(r"^2\.",self.conf["version"]) != None:
                    cmd = "%s -c %s -l %s -r %s -v --runmode=single --set \"stream.checksum-validation=no\"" % (self.conf["path"], self.conf["config"], self.conf["logdir"], self.pcapfile)
                else:
                    cmd = "%s -c %s -l %s -r %s" % (self.conf["path"], self.conf["config"], self.conf["logdir"], self.pcapfile)

        # Other runmodes should be equal
        else:
            if self.mode == "snort":
                cmd = "%s -c %s -l %s -K none -k none -r %s -A fast" % (self.conf["path"], self.conf["config"], self.conf["logdir"], pcap)
            elif self.mode == "suricata":
                if re.match(r"^2\.", self.conf["version"]) != None:
		    if "JIT" in self.conf["version"]:
		        cmd = "LD_LIBRARY_PATH=/opt/luajit20/lib/ %s -c %s -l %s -r %s -v --runmode=single --set \"stream.checksum-validation=no\"" % (self.conf["path"], self.conf["config"], self.conf["logdir"], pcap)
                    else:
		        cmd = "%s -c %s -l %s -r %s -v --runmode=single --set \"stream.checksum-validation=no\"" % (self.conf["path"], self.conf["config"], self.conf["logdir"], pcap)
		if re.match(r"^3\.", self.conf["version"]) != None:
		  cmd = "%s -c %s -l %s -r %s -v --runmode=single --set \"stream.checksum-validation=no\"" % (self.conf["path"], self.conf["config"], self.conf["logdir"], pcap)
                if re.match(r"^1\.",self.conf["version"]) != None:
		    if "JIT" in self.conf["version"]:
		        cmd = "LD_LIBRARY_PATH=/opt/luajit20/lib/ %s -c %s -l %s -r %s --runmode=single" % (self.conf["path"], self.conf["config"], self.conf["logdir"], pcap)
		    else:
		        cmd = "%s -c %s -l %s -r %s --runmode=single" % (self.conf["path"], self.conf["config"], self.conf["logdir"], pcap)
        return cmd

    def execute(self, runmode, pcap):
        if self.logfile and os.path.exists(self.logfile):
            try:
                os.remove(self.logfile)
                p_debug("Existing fastlog removed: %s" % self.logfile)
            except:
                p_warn("Failed to remove old fastlog: %s" % self.logfile)

            if self.perflogfile and os.path.exists(self.perflogfile):
                try:
                    os.remove(self.perflogfile)
                    p_debug("Existing perflog removed: %s" % self.perflogfile)
                except:
                    p_warn("Failed to remove old perflog: %s" % self.perflogfile)
        cmd = self.getCmd(runmode, pcap)
        p_info("Executing: %s" % cmd)

        #We should always run with ulimit unlimited.  This way we should always gen a core dump
        cmd = "ulimit -c unlimited; %s" % cmd
        #actually run the command
        self.returncode, self.stderr, self.stdout, self.elapsed = cmd_wrapper(cmd, 1)
        self.lastcmd = cmd
        # We store the returncode, stderr, stdout, elapsed time, in the engine instance
        # so that we can later add more inspections to only 1 run
        # (We could execute multiple run mode checks with just one run)
        return self.returncode

    #Acutally runs the IDS
    def run_ids(self, pcap, reporton):
        returncode = self.execute(self.Runmode.runmode, pcap)

        #look for errors and warnings in output with whatever self.returncode val
        (errors, warnings) = self.parse_ids_out(self.stderr,self.stdout)

        #check stderr for fast_pattern_debug and look for bad patterns
        if re.match(r"2(\.8\.6|\.9)","%s" % (self.conf["version"])) and "fpblacklist" in self.Runmode.conf["reportonarr"] and self.mode != "sanitize":
            fast_pattern_blacklist((self.stderr+self.stdout),self.Runmode.conf["fpblacklist"],self.Runmode.conf["fpcase"],self.Runmode.conf["fprulesglob"],self.Runmode.conf["globallogdir"])

        self.currentts = time.strftime("%Y-%m-%d-T-%H-%M-%S", time.localtime())
        #generate really basic stats about the run
        if "ids" in self.Runmode.conf["reportonarr"]:
            report = open("%s/%s-report-%s-%s.txt" % (self.Runmode.conf["globallogdir"], self.mode, str(self.currentts), str(os.path.basename(pcap))), 'w')
            report.write ('lastcmd:%s\n' % self.lastcmd)
            report.write ('elapsedtime:%f\n' % self.elapsed)
            report.write ('stderr:\n' + self.stderr)
            report.write ('stdout:\n' + self.stdout)
            report.write ('returncode:\n' + str(self.returncode))
            report.write ('errors:\n' + errors)
            report.write ('warnings:\n' + warnings)
            report.close()

        if self.returncode == 0:
            p_info("%s ran successfully" % self.mode)
            #move the alert log and update the global
            newfastlog = "%s/%s-%s-%s-%s.txt" % (self.conf["logdir"], self.engine, str(os.path.basename(self.fastlog)), str(self.currentts), str(os.path.basename(pcap)))
            p_debug("renaming fastlog %s to %s" % (self.logfile, newfastlog))
            os.rename(self.logfile, newfastlog)
            self.newfastlog = newfastlog
        
            #move the perf log and update the global
            p_debug("Perf log file should be %s" % self.perflogfile)
            if self.perflogfile and os.path.exists(self.perflogfile):
                newperflog = "%s/%s-%s-%s-%s.txt" % (self.conf["logdir"], self.engine, str(os.path.basename(self.perflog)), str(self.currentts), str(os.path.basename(pcap)))
                p_debug("renaming perflog %s to %s" % (self.perflogfile, newperflog))
                os.rename(self.perflogfile, newperflog)
                self.newperflog = newperflog

            self.httplog = "%s/http.log" % (self.conf["logdir"])
            if self.mode == "suricata" and os.path.exists(self.httplog):
                newhttplog = "%s/%s-%s-%s-%s.txt" % (self.conf["logdir"], self.engine, "http.log", str(self.currentts), str(os.path.basename(pcap)))
                os.rename(self.httplog, newhttplog)
                self.httplog = newhttplog
               
                
            #open up the log file and get a count of unique sids we see and a total non-preproc alerts
            if "idsperf" in self.Runmode.conf["reportonarr"]:
                print "Extracting IDS Perf stats"
                #if not os.path.exists(self.Runmode.conf["perfdb"]):
                #   p_error("%s: Could not find the perfdb %s\n" % (str(whoami()), self.Runmode.conf["perfdb"]))
                #   sys.exit(1)

                try:
                    fast = open (self.newfastlog)
                except:
                    p_error("%s: Could not open the fast log %s\n" % (str(whoami()), self.newfastlog))
                    sys.exit(1)
                        
                tmpsiddict = {}
                alertcnt = 0
                for line in fast:
                    m = self.regex["afast_full_parser"].match(line)
                    if m != None:
                        sid = m.group('sid')
                        src = struct.unpack("!I", socket.inet_aton(m.group('src')))[0] 
                        dst = struct.unpack("!I", socket.inet_aton(m.group('dst')))[0] 
                        gid = int(m.group('sid'))
                        rev = int(m.group('rev'))
                        msg = m.group('msg')
                        if m.group('class'):
                            classification =  m.group('class')
                        priority = m.group('prio')
                        proto = m.group('proto')
                        if m.group('dport'):
                           dport = int(m.group('dport'))
                        if m.group('sport'):
                           sport = int(m.group('sport'))
                        if not sid in tmpsiddict:
                            tmpsiddict[sid] = 1
                        else:
                            tmpsiddict[sid] += 1
                        alertcnt += 1
                    sqlcmd = 'INSERT INTO alerts(id, host, timestamp, runid, file, engine, alertfile, sid, gid, rev, msg, class, prio, proto, src, dst, sport, dport) VALUES(NULL,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)'
                    params=(self.host, self.currentts, self.runid, pcap, self.engine, self.newfastlog, sid, gid, rev, msg, classification, priority, proto, src, dst, sport, dport,)
                    try:
                        if self.db != None:
                            self.db.execute(sqlcmd,params)
                        else:
                            p_error("Db handler not valid")
                            sys.exit(2)
                    except:
                        p_error("failed to insert %s into perfdb\n" % (sqlcmd))
                        sys.exit(1)
                fast.close()
                sqlcmd = 'INSERT INTO filestats(id, host, timestamp, runid, cmd, file, engine, runtime, ualerts, alertfile, alertcnt, exitcode) VALUES(NULL,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)'
                params=(self.host, self.currentts, self.runid, self.lastcmd, pcap, self.engine, self.elapsed, str(tmpsiddict), self.newfastlog, alertcnt, self.returncode,)
                try:
                    if self.db != None:
                        self.db.execute(sqlcmd,params)
                    else:
                        p_error("Db handler not valid")
                        sys.exit(2)
                except:
                    p_error("failed to insert %s into perfdb\n" % (sqlcmd))
                    sys.exit(1)
                 #create table alerts (id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT UNIQUE, primary key (id), host text, timestamp text, runid text, file text, engine text, alertfile text, sid BIGINT UNSIGNED NOT NULL, gid BIGINT UNSIGNED NOT NULL,rev BIGINT UNSIGNED NOT NULL, msg text, class text, prio text, proto text, src INT UNSIGNED, dst INT UNSIGNED, sport int, dport int);
                 #self.regex["afast_full_parser"] = re.compile(r"^(?P<ts>[^\s]*)\s+?\[\*\*\]\s+?\[(?P<gid>\d+)\:(?P<sid>\d+)\:(?P<rev>\d+)\]\s+(?P<msg>.+?)\s+?\[\*\*\]\s+?(\[Classification\:\s+?(?P<class>[^\]]+)\]\s+?)?\[Priority\:\s+?(?P<prio>\d+?)\]\s+?{(?P<proto>UDP|TCP|ICMP|(PROTO\:)?\d+)\}\s(?P<src>\d+\.\d+\.\d+\.\d+)(:(?P<sport>\d+))?\s.+\s(?P<dst>\d+\.\d+\.\d+\.\d+)(:(?P<dport>\d+))?$")
            #if we have the perflog lets add this data to the db as well
            if "ruleperf" in self.Runmode.conf["reportonarr"]:
                perf_has_rev = False
                perf_has_disabled = False
                perf_is_suri = False
                bulk_insert = []
                print "Extracting Rule perf stats"
                #if not os.path.exists(self.Runmode.conf["perfdb"]):
                #    p_error("%s: Could not find the perfdb %s\n" % (str(whoami()), self.Runmode.conf["perfdb"]))
                #    sys.exit(1)
                 
                try:
                    perf = open (self.newperflog)
                except:
                    p_error("%s: Could not open the perf log of the engine %s\n" % (str(whoami()), self.engine))
                    print "%s: Could not open the perf log of the engine %s\n" % (str(whoami()), self.engine)
                    return 0

                #was using RE here but want this to be really fast if storing info on all rules    
                for line in perf:
                    line = line[:-1]
                    perf_vals = line.split( );
                    #we are only looking for gid's of 1 as we don't care about preproc generated events
                    if len(perf_vals) != 0 and perf_vals[0].isdigit():
                        if perf_is_suri == False:
                            #assign vars for perf info based on our captured regex.
                            #print m.group('rank') + ":" + m.group('sid')
                            rank = int(perf_vals[0])
                            sid = int(perf_vals[1])
                            gid = int(perf_vals[2])

                            #snort 2.8.4 doesn't have rev as an output column
                            #Num      SID GID     Checks   Matches    Alerts           Microsecs  Avg/Check  Avg/Match Avg/Nonmatch
                            #Num      Rule         Gid      Rev      Ticks        %      Checks   Matches  Max Ticks   Avg Ticks   Avg Match   Avg No Match
                            if perf_has_rev:
                                if len(perf_vals) != 12 and perf_has_disabled == True:
                                    p_error("skipping line with perf vals (%i):%s" % (len(perf_vals),line))
                                    continue
                                elif len(perf_vals) != 11 and perf_has_disabled == False:
                                    p_error("skipping line with perf vals (%i):%s" % (len(perf_vals),line))
                                    continue
                                rev = int(perf_vals[3])
                                checks = int(perf_vals[4])
                                matches = int(perf_vals[5])
                                alerts = int(perf_vals[6])
                                microsecs = int(perf_vals[7])
                                avgpercheck = float(perf_vals[8])
                                avgpermatch = float(perf_vals[9])
                                avgpernomatch = float(perf_vals[10])
                            else:
                                if len(perf_vals) != 10:
                                    p_error("skipping line:%s" % (line))
                                    continue
                                rev = 0
                                #if there were 0 checks skip it
                                checks = int(perf_vals[3])
                                matches = int(perf_vals[4])
                                alerts = int(perf_vals[5])
                                microsecs = int(perf_vals[6])
                                avgpercheck = float(perf_vals[7])
                                avgpermatch = float(perf_vals[8])
                                avgpernomatch = float(perf_vals[9])

                        elif perf_is_suri == True:
                            if len(perf_vals) != 12:
                                continue

                            rank = int(perf_vals[0])
                            sid = int(perf_vals[1])
                            gid = int(perf_vals[2])
                            rev = int(perf_vals[3])
                            microsecs = int(perf_vals[4])
                            checks = int(perf_vals[6])
                            matches = int(perf_vals[7])
                            #In suri alerts = matches
                            alerts = matches
                            avgpercheck = float(perf_vals[9])
                            avgpermatch = float(perf_vals[10])
                            avgpernomatch = float(perf_vals[11])

                        #dump these stats into a db
                        bulk_insert.append((self.host, self.currentts, self.runid, pcap, self.newfastlog, self.engine, rank, sid, gid, rev, checks, matches, alerts, microsecs, avgpercheck, avgpermatch, avgpernomatch))
                    else:
                        if re.search(r"Avg\sNo\sMatch",line) != None:
                            perf_is_suri = True

                        if re.search(r"\srev\s",line,re.I) != None:
                            perf_has_rev = True
                        
                        if re.search(r"\sdisabled",line,re.I) != None:
                            perf_has_disabled = True 

                        if re.search(r"\salerts\s",line,re.I) != None:
                            perf_has_alerts = True
                    #else:
                        #print "invalid perfstat line %s" % line
                perf.close()
                qstring = """INSERT INTO rulestats (id, host, timestamp, runid, file, alertfile, engine, rank, sid, gid, rev, checks, matches, alerts, microsecs, avgtcheck, avgtmatch, avgtnomatch) VALUES(NULL, %s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)"""
                self.db.mass_execute(qstring, bulk_insert)

		#Ok, what to do here? return code is 0, but we got errors, and/or warnings
            if errors != "" or warnings != "":
                if errors == "":
                    errors = "None"
                if warnings == "":
                    warnings = "None"
                emailsubject = "ETPRO2 QA ERROR"
                emailbody = "mode:%s; lastcmd:%s; returncode:%i; elapsed:%f; Errors:\n%s\n Warnings:\n%s\n stderr:\n%s\n stdout:\n%s\n " % (self.mode, self.lastcmd, self.returncode, self.elapsed, errors, warnings, self.stderr, self.stdout)
                #emailbody = "mode:%s\nself.lastcmd:%s\nself.returncode:%i\nself.elapsed:%f\nErrors:\n%s\nWarnings:\n%s\n\n" % (self.mode, self.lastcmd, self.returncode, self.elapsed, errors, warnings)
                p_info(emailbody)
                #send_email(str(self.options.emailsubject) + emailsubject,emailbody) 
					
            return 0
        else:
            p_info("%s ran with errors" % self.mode)
            emailsubject = "ETPRO2 QA ERROR"
            if errors == "":
                errors = "None"
            if warnings == "":
                warnings = "None"
            emailbody = "mode:%s; lastcmd:%s; returncode:%i; elapsed:%f; Errors:\n%s\n Warnings:\n%s\n stderr:\n%s\n stdout:\n%s\n " % (self.mode, self.lastcmd, self.returncode, self.elapsed, errors, warnings, self.stderr, self.stdout)
            p_info(emailbody)
            #send_email(str(self.options.emailsubject) + emailsubject,emailbody) 
            return 1


    def run(self, runmode, pcap = None):
        if runmode == "sanitize":
            self.sanitize()
        if runmode == "verify":
            self.verify2()
        if runmode == "xtract":
            self.xtract(pcap)
        if runmode == "xtractall":
            self.xtractall(pcap)
        if runmode == "sidperfq":
            self.sidperfreport()
        if runmode == "dumbfuzz":
            self.dumbfuzz(pcap)

    #parse stderr, and stdout from the IDS looking for Error and Warning lines
    #TODO: summary of error and warning lines, e-mail on error or warnings if treat warning as errors
    def parse_ids_out(self,stderr,stdout):
        self.rule_warnings = []
        self.rule_errors = []

        warnings = self.warnings
        errors = self.errors
        for line in stderr.split('\n'):
            m = self.regex["error"].match(line)
            if m != None and self.regex["ignore"].match(line) == None: 
                p_info("%s: Error found in stderr\n%s" % (str(whoami()),line))
                errors.append(line)
                self.errcnt = self.errcnt + 1
            m = self.regex["warning"].match(line)
            if m != None and self.regex["ignore"].match(line) == None:
                p_info("%s: Warning found in stderr\n%s" % (str(whoami()),line))
                warnings.append(line)
                self.warncnt = self.warncnt + 1
                problem_on_previous = 1

            if self.mode == "snort":
                m = self.regex["rule_warn_snort"].match(line)
            else:
                m = self.regex["rule_warn_suricata"].match(line)
 
            if m != None and self.regex["ignore"].match(line) == None:
                p_info("%s: rule warning found in stderr\nfile: %s (line %s)" % (str(whoami()),m.group("file"),m.group("line")))
                self.rule_warnings.append((m.group("file"),m.group("line"), line))

            if self.mode == "snort":
                m = self.regex["rule_err_snort"].match(line)
            else:
                m = self.regex["rule_err_suricata"].match(line)

            if m != None and self.regex["ignore"].match(line) == None:
                p_info("%s: rule error found in stderr\nfile: %s (line %s)" % (str(whoami()),m.group("file"),m.group("line")))
                self.rule_errors.append((m.group("file"),m.group("line"), line))

        for line in stdout.split('\n'):
            m = self.regex["error"].match(line)
            if m != None and self.regex["ignore"].match(line) == None: 
                p_info("%s: Error found in stdout\n%s" % (str(whoami()),line))
                errors.append(line)
                self.errcnt = self.errcnt + 1

            m = self.regex["warning"].match(line)
            if m != None and self.regex["ignore"].match(line) == None:
               p_info("%s: Warning found in stdout\n%s" % (str(whoami()),line))
               warnings.append(line)
               self.warncnt = self.warncnt + 1

            if self.mode == "snort":
                m = self.regex["rule_warn_snort"].match(line)
            else:
                m = self.regex["rule_warn_suricata"].match(line)

            if m != None and self.regex["ignore"].match(line) == None:
                p_info("%s: rule warning found in stdout\nfile: %s (line %s)" % (str(whoami()),m.group("file"),m.group("line")))
                self.rule_warnings.append((m.group("file"),m.group("line"), line))

            if self.mode == "snort":
                m = self.regex["rule_err_snort"].match(line)
            else:
                m = self.regex["rule_err_suricata"].match(line)

            if m != None and self.regex["ignore"].match(line) == None:
                p_info("%s: rule error found in stdout\nfile: %s (line %s)" % (str(whoami()),m.group("file"),m.group("line")))
                self.rule_errors.append((m.group("file"),m.group("line"), line))
        if re.match(r'2\.4',"%s" %(self.conf["version"])) and self.mode == "snort":
            for m in self.regex["rule_warn_snort_multi_line"].finditer((stderr+stdout)):
                p_info("%s: rule warning found in combined output \nfile: %s (line %s)" % (str(whoami()),m.group("file"),m.group("line")))
                self.rule_warnings.append((m.group("file"),m.group("line"), m.group(0).replace('\n', '')))
                self.warncnt = self.warncnt + 1
            for m in self.regex["rule_err_snort_multi_line"].finditer((stderr+stdout)):
                p_info("%s: rule error found in combined output \nfile: %s (line %s)" % (str(whoami()),m.group("file"),m.group("line")))
                self.rule_errors.append((m.group("file"),m.group("line"), m.group(0).replace('\n', '')))
                self.errcnt = self.errcnt + 1

        err_str = ""
        for er in errors:
            err_str = "%s- %s\n" % (err_str, er)
        warn_str = ""
        for warn in warnings:
            warn_str = "%s- %s\n" % (warn_str, warn)

        self.err_str = err_str
        self.warn_str = warn_str
        return (err_str, warn_str)


# Container for all engines configs
class IDSEngineContainer:
    def __init__(self, engines):
        self.engines = {}
        try:
            l = glob(engines)
            for enginedef in l:
                p_debug("Loading %s" % enginedef)
                f = open(enginedef, "r")
                engines = yaml.load(f.read())
                f.close()
                for engine in engines['engines']:
                    self.engines[engine['engine']] = IDSEngine(engine)
        except:
            p_error("No engines defined, or invalid yaml syntax")
            sys.exit(-60)
    def __str__(self):
        i = 0
        s = "\nListing Engines:\n\n"
        for engine in self.engines.values():
            s = "%s---  Engine %d (%s)  ---\n" % (s, i + 1, engine.conf["engine"])
            s = "%s%s\n" % (s, str(engine))
            s = "%s-------------------\n\n" % s
            i = i +  1
        if i == 0:
            s = "%s Has no engines defined at config\n" % s
        return s

