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

import os
import sys
import yaml
import glob
from collections import defaultdict
from optparse import OptionParser

from IDSEngine import *
from IDSUtils import *
from IDSMail import *
from IDSRunmodeCompare import *
from IDSRunmodeSidperfq import *
from IDSLogging import *
from IDSdb import *

# If b has a key, set it/overwrite it in a
def overrideOption(a, b, k):
    if b.has_key(k) and b[k]:
        a[k] = b[k]
        p_debug("Setting %s from cli" % k)
    # Here we can also set default values if none is specified at config

# If b has a key, set it/overwrite it in a
def appendOverrideOption(a, b, k):
    if b.has_key(k) and b[k]:
        if a.has_key(k):
            a[k] = a[k] + b[k]
        else:
            a[k] = b[k]
        p_debug("Setting %s from cli" % k)
    # Here we can also set default values if none is specified at config

# Inheritance of runmode compare (not engine independent runmode)
# and RunmodeSidperfq to allow queries without engine executions
class IDSToolEnv(RunmodeCompare, RunmodeSidperfq):
    def __init__(self, confmap):
        self.confmap = confmap
        # print str(self.confmap)

        mail_opts = self.getConfVal('mail_options')
        if mail_opts != None:
            self.Mail = IDSMail(mail_opts)
        else:
            self.Mail = IDSMail(None)

        server_opts = self.getConfVal('server_options')
        if server_opts:
            self.Server = IDSServer(server_opts)
        else:
            self.Server = IDSServer(None)

        pcap_opts = self.getConfVal('pcap_options')
        if pcap_opts:
            self.Pcap = IDSPcap(pcap_opts)
        else:
            self.Pcap = IDSPcap(None)

        runmode_opts = self.getConfVal('runmode_options')
        if runmode_opts:
            self.Runmode = IDSRunmode(runmode_opts)
        else:
            self.Runmode = IDSRunmode(None)

        editcap_opts = self.getConfVal('editcap_options')
        if editcap_opts:
            self.Editcap = IDSEditcap(editcap_opts)
        else:
            self.Editcap = IDSEditcap(None)

        signature_opts = self.getConfVal('signature_options')
        if signature_opts:
             self.Signature = IDSSignature(signature_opts)
        else:
            self.Signature = IDSSignature(None)

        db_opts = self.getConfVal('db_options')
        if db_opts:
            self.db = IDSdb(db_opts)
        else:
            p_info("No db provided")

        self.conf_version = self.getConfVal('config_version')
        if not self.conf_version:
            self.conf_version = "0.2"

        self.host = self.getConfVal('host')
        if not self.host:
            self.host = "localhost"

        engines = self.getConfVal('engine_definitions')
        if engines:
            self.EngineMgr = IDSEngineContainer(engines)
        else:
            # Fatal error
            p_error("Error, no engine config was provided")
            sys.exit(-15)

        #Regex for file compare options in format file1:mode1,file2:mode2
        self.regex = {}
        self.regex["cmpropts"] = re.compile(r"^(?P<file1>.+)\:(?P<mode1>.+)\,(?P<file2>.+)\:(?P<mode2>.+)$")
        #Regex for matching on alert fast formated log files with GID of one. If somebody else wants to add support for .so rule etc go for it
        self.regex["afast"] = re.compile(r".+\[1\:(?P<sid>\d+)\:\d+\].+\{(?P<proto>UDP|TCP|ICMP|(PROTO\:)?\d+)\}\s(?P<src>\d+\.\d+\.\d+\.\d+)(:(?P<sport>\d+))?\s.+\s(?P<dst>\d+\.\d+\.\d+\.\d+)(:(?P<dport>\d+))?")


    # Use this one for generic options
    def getConfVal(self, key):
        try:
            val = self.confmap[key]
        except:
            p_debug("The key %s doesn't exist" % key)
            # We could add here generic values
            val = None
        return val


    def __str__(self):
        s = ''
        s = '%sConfig options loaded: \n' % (s)
        s = '%sconfig_version: %s\n' % (s, self.conf_version)
        s = '%s%s\n' % (s, self.EngineMgr)
        s = '%s%s\n' % (s, self.Server)
        s = '%s%s\n' % (s, self.Pcap)
        s = '%s%s\n' % (s, self.Runmode)
        s = '%s%s\n' % (s, self.Editcap)
        s = '%s%s\n' % (s, self.Signature)
        s = '%s%s\n' % (s, self.Mail)
        return s

    def run(self):
        pcaplist = []
        pcaplisttmp = []
        ignorelist = ""
        #loopcnt = 0
        self.currentts = time.strftime("%Y-%m-%d-T-%H-%M-%S", time.localtime())

        #Generate a specific run-id for this run in the format of runmode-timestamp
        self.runid = "%s-%s" %(str(self.Runmode.runmode),time.strftime("%Y-%m-%d-T-%H-%M-%S", time.localtime()))
        for engine in self.targets:
            e = self.EngineMgr.engines[engine]
            e.runid = self.runid
            e.db = self.db
            e.host = self.host

            #Global Override
            if self.Runmode.conf.has_key("glogoverride") and self.Runmode.conf.has_key("globallogdir"):
                e.conf["logdir"] = self.Runmode.conf["globallogdir"]

            #RunID Dir appended
            if self.Runmode.conf.has_key("appendrunid") and self.Runmode.conf["appendrunid"]:
                if e.conf["logdir"]:
                    e.conf["logdir"] = "%s/%s" % (e.conf["logdir"],self.runid)
                    if not os.path.exists(e.conf["logdir"]):
                        try:
                           os.mkdir(e.conf["logdir"])
                        except:
                           p_error("%s: failed to make directory %s\n" % (str(whoami()),e.conf["logdir"]))
                           sys.exit(1)

                self.Runmode.conf["globallogdir"] = "%s/%s" % (self.Runmode.conf["globallogdir"],self.runid)

                #No Reason to try and create again if we merged them
                if e.conf["logdir"] != self.Runmode.conf["globallogdir"] and not os.path.exists(self.Runmode.conf["globallogdir"]):
                    try:
                        os.mkdir(self.Runmode.conf["globallogdir"])
                    except:
                        p_error("%s: failed to make directory %s\n" % (str(whoami()),self.Runmode.conf["globallogdir"]))
                        sys.exit(1)

            #EngineID Dir Appended probably only makes sense for non-global log dir!?!?
            if self.Runmode.conf.has_key("appendengineid") and self.Runmode.conf["appendengineid"]:
                if e.conf["logdir"]:
                    e.conf["logdir"] = "%s/%s" % (e.conf["logdir"],e.conf["engine"])
                    if not os.path.exists(e.conf["logdir"]):
                        try:
                            os.mkdir(e.conf["logdir"])
                        except:
                            p_error("%s: failed to make directory %s\n" % (str(whoami()),e.conf["logdir"]))
                            sys.exit(1)

            # We setup defaults elsewhere TODO: cleaner version of this we end up setting twice.
            e.logfile = "%s/%s" % (e.conf['logdir'], e.conf['fastlog'])
            e.perflogfile = "%s/%s" % (e.conf['logdir'], e.perflog)

        # All the runmodes that doesn't compare the output of different engines should be in the following list
        # (All that can be independently executed)
        if self.Runmode.runmode in ["sanitize", "verify", "sidperfq"]:
            for engine in self.targets:
                e = self.EngineMgr.engines[engine]

                # And now execute the engine through the runmode
                if self.Runmode.runmode in ["sanitize", "verify"]:
                    e.run(self.Runmode.runmode)
                elif  self.Runmode.runmode == "sidperfq":
                    # First check sperfsid
                    if self.Runmode.conf.has_key("sperfsid") and self.Runmode.conf["sperfsid"].isdigit() and self.Runmode.conf.has_key("perfdb") and os.path.exists(self.Runmode.conf["perfdb"]):
                        e.run(self.Runmode.runmode)
                    else:
                        p_error("<%s><%s><%s>: sid provided via --sperfsid %s is invalid or None and/or --perfdb %s option was invalid or not provided" % (str(whoami()),str(lineno()),str(__file__),str(self.Runmode.conf["sperfsid"]),str(self.Runmode.conf["perfdb"])))
                        sys.exit(-19)

        # Comparison modes here
        elif self.Runmode.runmode == "comparefast":
            if self.Runmode.conf.has_key("cmpropts"):
                self.comparefast(self.Runmode.conf["cmpropts"])
            else:
                p_error("%s: cmpropts is a required argument for the comparefast runmode the options should be passed like --cmpropts=\"file1:mode1,file2:mode2\"")
                sys.exit(1)


        # The looping runmodes should go here
        elif self.Runmode.runmode in ["run","dumbfuzz","xtract","rcomparefast"]:
            if self.Signature.conf.has_key("xtractignore") and self.Signature.conf["xtractignore"]:
                self.xignore = self.parse_xtract_ignore()
            else:
                self.xignore = []

            globlist = []

            # hack to get around those of us used to perl globbing.  Globs can be specified as a list
            if self.Pcap.conf.has_key("pcappath") and self.Pcap.conf["pcappath"]:
                globlist = get_glob_list(self.Pcap.conf["pcappath"])
            else:
                p_error("<%s><%s><%s> You must specify suppy a pcap file or a list of pcap files with --pcapppath wildcards are supported\n" % (str(whoami()),str(lineno()),str(__file__)))
                sys.exit(1)

            if self.Pcap.conf.has_key("pcapignore") and self.Pcap.conf["pcapignore"]:
                ignorelist = get_glob_list(self.Pcap.conf["pcapignore"])
            else:
                ignorelist = []

            for pcap in ignorelist:
                if pcap in globlist: globlist.remove(pcap)

            if not globlist:
                p_error("Pcap list empty...bailing")
                sys.exit(1)

            if self.Pcap.conf.has_key("sortpcaps") and self.Pcap.conf["sortpcaps"]:
                if self.Pcap.conf["sortpcaps"] == "size":
                    for pcapfile in globlist:
                        stats = os.stat(pcapfile)
                        pcap_tuple = stats.st_size, pcapfile
                        pcaplisttmp.append(pcap_tuple)
                        pcaplisttmp.sort()
                    for pcap_t in pcaplisttmp:
                        pcaplist.append(pcap_t[1])

                elif self.Pcap.conf["sortpcaps"] == "random":
                    random.shuffle(globlist, random.random)
                    pcaplist = globlist
                    p_debug(str(pcaplist))
                else:
                    pcaplist = globlist

            #The number of times we are going to loop throug the tests if it is a digit
            #we convert to the digit if it is the string forever we leave it as a string
            #in this case loopcnt will always be less than a string
            if self.Runmode.conf.has_key("loopnum"):
                if self.Runmode.conf["loopnum"].isdigit():
                    self.convloop = int(self.Runmode.conf["loopnum"])
                elif self.Runmode.conf["loopnum"] != None and self.Runmode.conf["loopnum"] == "forever":
                    self.convloop = self.Runmode.conf["loopnum"]
            else:
                p_debug("invalid loopnum... defaulting to 1")
                self.Runmode.conf["loopnum"] = 1
                self.convloop = self.Runmode.conf["loopnum"] = 1

            p_info("looping %s times in runmode %s" % (str(self.convloop), self.Runmode.runmode))

            if self.Runmode.runmode in ["xtract","run","dumbfuzz"]:
                for engine in self.targets:
                    loopcnt = 0
                    e = self.EngineMgr.engines[engine]
                    # Let each engine know the xignore list
                    e.xignore = self.xignore
                    #for loopcnt in range(0, int(self.convloop)):
                    while loopcnt < self.convloop :
                        p_info("run with success %i out of %s" % (loopcnt, str(self.convloop)))
                        for pcap in pcaplist:
                            self.sidd = {}
                            if self.Runmode.runmode == "run":
                                e.run_ids(pcap, "yes")
                            elif self.Runmode.runmode == "xtract":
                                e.run(self.Runmode.runmode, pcap)
                            elif self.Runmode.runmode == "dumbfuzz":
                                e.run(self.Runmode.runmode, pcap)
                        loopcnt += 1
            elif self.Runmode.runmode == "rcomparefast":
                if len(self.targets) != 2:
                    p_error("Error, \"%s\" requires 2 (and only 2) target engines. Got %d engines. Use -L to list the engines available. Exiting..." % (self.Runmode.runmode, len(self.targets)))
                    sys.exit(-21)
                # Recursive compare
                for loopcnt in range(0, int(self.convloop)):
                    p_info("run with success %i out of %s" % (loopcnt, str(self.convloop)))
                    for pcap in pcaplist:
                        self.sidd = {}
                        # TODO: Check that it passes only 2 target engines
                        self.rcomparefast(pcap)
            else:
                p_warn("No runmode selected" % self.Runmode.runmode)

        else:
            p_error("Unknown runmode?? %s??" % self.Runmode.runmode)

        #once we are done looping gen perf report if option specified
        if self.Runmode.conf.has_key("reportonarr"):
            if "TopNWorstAll" in self.Runmode.conf["reportonarr"]:
                self.TopNWorstAll()
            if "TopNWorstCurrent" in self.Runmode.conf["reportonarr"]:
                self.TopNWorstCurrent()
            if "LoadReportCurrent" in self.Runmode.conf["reportonarr"]:
                self.LoadReportCurrent()

        if self.Runmode.conf.has_key("sqlquery") and self.Runmode.conf["sqlquery"] != "":
            self.queryDB(self.Runmode.conf["sqlquery"])


    # This is the function
    # used to override the default config with the cli options
    def setCliOpts(self, options):
        #try:
            #print "Options: %s" % options
            # Default values are loaded from the config file, but we might want to specify custom settings from cli
            # so let's overwrite them
            # Editcap options
            for v in ["eratio"]:
                overrideOption(self.Editcap.conf, options.__dict__, v)
            # Pcap options
            for v in ["pcappath", "pcapignore", "sortpcaps"]:
                overrideOption(self.Pcap.conf, options.__dict__, v)
            # Signature options
            for v in ["xtractignore"]:
                overrideOption(self.Signature.conf, options.__dict__, v)
            # Runmode options
            for v in ["runmode", "reportdb", "perfdb", "loopnum", "verifyconf", "reporton",
"parseout ", "warnaserror", "globallogdir", "topN", "appendrunid", "cmpropts",
"snortrules", "surirules", "sperfsid", "enableallrules", "fpblacklistopts",
"reportgroup",
"usecustomrules", "usesnortvalidator", "usedumbpig", "sqlquery","appendengineid","glogoverride"]:
                overrideOption(self.Runmode.conf, options.__dict__, v)
            if self.Runmode.conf.has_key("reporton") and self.Runmode.conf["reporton"]:
                self.Runmode.conf["reportonarr"] = self.Runmode.conf["reporton"].split(",")
                if "TopNWorstAll" in self.Runmode.conf["reportonarr"] or "TopNWorstCurrent" in self.Runmode.conf["reportonarr"] and not "ruleperf" in self.Runmode.conf["reportonarr"]:
                    self.Runmode.conf["reportonarr"].append("ruleperf")

                if "fpblacklist" in self.Runmode.conf["reportonarr"] and self.Runmode.conf.has_key("fpblacklistopts"):
                    m = re.match(r"^(?P<fpblacklist>.+)\:(?P<fpcase>(case|nocase))(\:(?P<fprulesglob>.+))?$",self.Runmode.conf["fpblacklistopts"])
                    if m:
                        #set the blacklist file
                        if m.group("fpblacklist") and os.path.exists(m.group("fpblacklist")):
                            self.Runmode.conf["fpblacklist"] = m.group("fpblacklist")
                        else:
                            p_error("%s: could not find the fast_pattern blacklist specified %s" % (str(whoami()), m.group("fpblacklist")))
                            sys.exit(1)

                        #set the case to one the two options
                        self.Runmode.conf["fpcase"] = m.group("fpcase")

                        if m.group("fprulesglob"):
                            self.Runmode.conf["fprulesglob"] = m.group("fprulesglob")
                        else:
                            self.Runmode.conf["fprulesglob"] = None
                    else:
                        p_error("%s: invalid option provided in fpblacklistopts string %s" % (str(whoami()),self.Runmode.conf["fpblacklistopts"]))
                        sys.exit(1)
                elif "fpblacklist" in self.Runmode.conf["reportonarr"]:
                    p_error("fpblacklist used in --reporton but opitons not passed via --fpblacklistopts")
                    sys.exit(1)

                if "LoadReportCurrent" in self.Runmode.conf["reportonarr"] and not "idsperf" in self.Runmode.conf["reportonarr"]:
                    self.Runmode.conf["reportonarr"].append("idsperf")
            else:
                self.Runmode.conf["reportonarr"] = []

            # Mail options
            for v in ["emailon","emailsrc", "emaildst", "emailsrv"]:
                overrideOption(self.Mail.conf, options.__dict__, v)

            for v in ["emailon"]:
                overrideOption(self.Runmode.conf, options.__dict__, v)

            appendOverrideOption(self.Mail.conf, options.__dict__, "emailsubject")

            # split email on
            if self.Runmode.conf.has_key("emailon") and self.Runmode.conf["emailon"]:
                self.Runmode.conf["emailonarr"] = self.Runmode.conf["emailon"].split(",")
            else:
                self.Runmode.conf["emailonarr"] = []

            #glob list of rules were we want to enable disabled sigs
            if self.Runmode.conf.has_key("enableallrules"):
               enable_all_rules(self.Runmode.conf["enableallrules"])

            # XXXDR: where should we place the following:
            # "perfdb", "loopnum", "verifyconf", "reporton", "parseout ","warnaserror","globallogdir","topN","appendrunid","cmpropts","snortrules","surirules","sperfsid"]
            # atm I'm storing them into the runmode object

            if options.__dict__.has_key("target-opts") and options.__dict__["target-opts"]:
                target_opts = options.__dict__["target-opts"]
                # Parse opts
                opts_array = target_opts.split(";")
                for opts in opts_array:
                    # Get the engine ("all" should change all the engines config)
                    t = opts.split(":")[0].strip()
                    optvars = opts.split(":")[1].strip()
                    p_debug("Setting opts from cli to: %s" % t)
                    p_debug("Optvars: %s" % optvars)
                    varopt = optvars.split(",")
                    vdict = {}
                    for v in varopt:
                        varname = v.split("=")[0].strip()
                        varval = v.split("=")[1].strip()
#{'engine': 'snort2861pro', 'enable': True, 'log': 'lalala', 'type': 'snort', 'fastlog': 'alert', 'lolo': 'lololoolo', 'summary': 'snort 2.8.6.1 with config of ET pro rules', 'version': '2.8.6.1', 'logdir': './logs/', 'path': '/opt/snort2861/bin/snort', 'config': '/opt/snort2861/etc/snort-et-pro.conf', 'configtpl': '/opt/snort2861/etc/snort.conf.tpl'}
                        if varname in ['enable', 'fastlog', 'summary', 'version', 'logdir', 'path', 'config', 'configtpl', 'customrules']:
                            vdict[varname] = varval
                            p_debug("Setting %s to %s" % (varname, varval))
                        else:
                            p_warn("We cannot set the var %s" % varname)

                    tdict = {}
                    if t == "all":
                        tdict = self.EngineMgr.engines
                    else:
                        if self.EngineMgr.engines.has_key(t) and self.EngineMgr.engines[t]:
                            tdict[t] = self.EngineMgr.engines[t]
                        else:
                            p_warn("Engine not configured (%s). This means that you should set all the engine config variables from the target-opts" % t)
                            # If we want to be able to create engine configs on the fly, here we should
                            # check that all the vars needed for a minimum engine configuration are set
                            # from cli, and create an instance of a new engine here

                    for e in tdict.values():
                        for vname in vdict.keys():
                            overrideOption(e.conf,vdict, vname)

            #Return options with the new values set
            return options

