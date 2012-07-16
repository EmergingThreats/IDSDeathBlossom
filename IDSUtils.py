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

import re
import glob
import os
import time
import random
import smtplib
import inspect
import sys

from IDSLogging import *
from collections import defaultdict
from optparse import OptionParser
from subprocess import Popen, PIPE
from tempfile import mkstemp
from scapy.all import *

class IDSRunmode:
    def __init__(self, runmode_options):
        #print str(runmode_options)
        self.conf = runmode_options

    def __str__(self):
        return "Runmode options: \n%s" %str(self.conf)


class IDSEditcap:
    def __init__(self, editcap_options):
        #print str(editcap_options)
        self.conf = editcap_options

    def __str__(self):
        return "Editcap options: \n%s" %str(self.conf)


# As soon as we add more pcap functions, we should create a new file with this class
class IDSPcap:
    def __init__(self, pcap_options):
        #print str(pcap_options)
        self.conf = pcap_options

    def gen_dummy_pcap(self):
        pkt = IP()/TCP()/"Dummy!!"
        (a,filename) = mkstemp("", "","/tmp")
        wrpcap(filename, pkt)
        return filename
    
    def __str__(self):
        return "Pcap options: \n%s" %str(self.conf)


class IDSServer:
    def __init__(self, server_options):
        #print str(server_options)
        self.conf = server_options

    def __str__(self):
        return "Server options: \n%s" %str(self.conf)

#get current function name
#http://stefaanlippens.net/python_inspect
def whoami():
    return inspect.stack()[1][3]

def cmd_wrapper(cmd, quite):
    #run our command 
    if quite == 0:
        p_info("running: %s" % str(cmd))
    start = time.time()
    p = Popen(cmd, stdout=PIPE, stdin=PIPE, stderr=PIPE, shell=True)
    stdout, stderr = p.communicate()

    #wait on the process and print the return code
    elapsed = time.time() - start
    if quite == 0:
        p_info("return code: %s" % str(p.returncode))
        p_info("runtime: %s" % str(elapsed))
    if p.returncode == 0:
        return (p.returncode, stderr, stdout, elapsed)
    else:
        p_warn("there was an error executing %s" % cmd)
        if quite == 0:
            print "stderr:"
            print stderr
            print "stdout:"
            print stdout
        return (p.returncode, stderr, stdout, elapsed)
    
#get the current line number
#http://code.activestate.com/recipes/145297-grabbing-the-current-line-number-easily/
def lineno():
    """Returns the current line number in our program."""
    return inspect.currentframe().f_back.f_lineno

#get the localhost name via socketlib
def get_local_fqdn():
    import socket
    hostname = socket.gethostname()
    #this probably isn't needed but sitting in a pizza hut in Hill City KS let's assume we do need it...
    hostfqdn = socket.getfqdn(hostname)
    return hostfqdn

#given a string like /dir1/*.pcap,/dir2/*.pcap glob each item in the list avoiding dupes. Python glob is rather limited can't do /{dir1,dir2}/*.pcap
def get_glob_list(globslist):
    import glob
    tmpgloball=[]
    tmparr=globslist.split(",")
    for globstring in tmparr:
        tmpglob = glob.glob(globstring)
        for gfile in tmpglob:
            if gfile not in tmpgloball:
                tmpgloball.append(gfile)
    return tmpgloball

# Given a glob expr list (comma separated), create a template config for snort or suri withit
def generate_config(engine_type, globexpr, configtpl =""):
    try:
        if not os.path.isfile(configtpl):
            p_error("Template config %s not valid" % configtpl)
            return None

        # Read the config
        f = open(configtpl, "r")
        data = f.read()
        f.close()

        (a,filename) = mkstemp("", "","/tmp")
        p_debug("FILETEMP: %s" % filename)

        f = open(filename,"w")
        f.write(data)
        # Append rules
        globlist = get_glob_list(globexpr)
        if not globlist:
            p_error("The glob expression %s didn't resolv any path. Exiting..." % str(globexpr))
            sys.exit(-10)
        p_info("Loading glob result: %s" % str(globlist))
        if engine_type == "snort":
            for rulefile in globlist:
                f.write("include %s\n" % rulefile)
    
        elif engine_type == "suricata":
            for rulefile in globlist:
                f.write("  - %s\n" % rulefile)
        f.close()
    except:
        p_error("Error creating template")
        sys.exit(-11)
    return filename

def fast_pattern_blacklist(snortoutput,blacklist_file,nocase,rulesglob,logdir):
    #one long nasty regex.. most people would put an \n in here somewhere but I'm not most men.
    fpdebug_regex = re.compile(r"(?P<gid>\d)\:(?P<sid>\d+)\n\s+Fast pattern matcher\:\s+(?P<fmatcher>[^\n]+)\n\s+Fast pattern set\:\s+(?P<fpset>[^\n]+)\n\s+Fast pattern only\:\s+(?P<fponly>[^\n]+)\n\s+Negated\:\s+(?P<fpnegate>[^\n]+)\n\s+Pattern offset\,length\:\s+(?P<fpoffset>[^\n]+)\n\s+Pattern truncated\:\s+(?P<fptruncated>[^\n]+)\n\s+Original pattern\n\s+\x22(?P<fporiginal>[^\x22]+)\x22\n\s+Final pattern\n\s+\x22(?P<fpfinal>[^\x22]+)\x22\n", re.IGNORECASE)
    blacklist = parse_blacklist(blacklist_file)
    reportfile = "%s/fast-pattern-blacklist-report.txt" % (logdir)
    report = open(reportfile, 'w')
    report.write("Bad Patterns Report:\n")
    matchcnt = 0;
    finditercnt = 0;

    for match in fpdebug_regex.finditer(snortoutput):
        for blmatch in blacklist:
            blmatch = blmatch.strip()

            #this is stupid lazy this belongs in another function
            havematch = "no"

            if nocase == True:
                if match.group("fpfinal").lower() == blmatch.lower():
                     report.write("Match of case insensitive Blacklist Entry:%s\n" % (blmatch))
                     report.write("%s\n" % (match.group(0)))
                     havematch = "yes"
                     matchcnt += 1
            else:   
                if match.group("fpfinal") == blmatch:
                     report.write("Match of Blacklist Entry:%s\n" % (blmatch))
                     report.write("%s\n" %(match.group(0)))
                     havematch = "yes"
                     matchcnt += 1
            if rulesglob and havematch == "yes":
                rulearr =  find_sid(match.group("sid"),rulesglob)
                for entry in rulearr:
                    (rfile,sid,rule) = entry
                    if rule is not None:
                        report.write("rules matching sid:%s\nfile:%s\n%s\n" % (sid,rfile,rule))
        finditercnt += 1
    if finditercnt > 0:
        report.write("Total bad patterns found %i for %i checks\n" % (matchcnt,finditercnt))
    else:
        report.write("Could not find fast_pattern debug output in stderr/stdout\n")

    report.close()
    return reportfile
#parse the blacklist careful no validation garbage in garbage out.
def parse_blacklist(black_list_file):
    if os.path.exists(black_list_file):
        try:
            blfile = open(black_list_file)
            blacklist = blfile.readlines()
            if blacklist == []:
                p_error("blacklist file was parsed but is empty bailing")
                sys.exit(1)
            return blacklist
        except:
            p_error("failed to open and read blacklist pattern file %s" % (black_list_file))
            sys.exit(1)
    else:
        p_error("failed to find blacklist pattern file %s" % (black_list_file))
        sys.exit(1)

# Given a glob list and a regex expr, search the matching rules and return
# the first file found with that expr, line number and rule or all the occurences
def grep_rules(regexp, ruleglob, flag_all = 0):
    globlist = get_glob_list(ruleglob)
    #print str(globlist)
    m = None
    result = []
    sidregex = re.compile(regexp)
    for fil in globlist:
        m = None
        if not os.path.isfile(fil):
            continue
        f = open(fil,"r")
        i = 0
        for line in f:
            i = i + 1
            p_debug(str(i) + " " + line)
            m = sidregex.search(line)
            if m:
                p_debug("Sid of \"%s\" found" % str(regexp))
                break
        f.close()
        if m:
            result.append((fil, i, line))
            if flag_all == 0:
                return result
    return result

# Given a glob list and a sid, search the rule and return
# the first file found with that sid, line number and rule or all
# the occurrences 
def find_sid(sid, ruleglob, flag_all = 0):
    return grep_rules("sid\s*:\s*%s\s*(;|\))" % sid, ruleglob, flag_all)

#enable all commented out rules TODO: add option of generate a new rulesfile or modifying the file in place
def enable_all_rules(rulesglob):

    disabled_rule_re = re.compile(r"^\s*#+\s*(?P<action>(alert|log|pass|drop|reject|sdrop))")
    rule_file_list = get_glob_list(rulesglob)
    for rules_file in rule_file_list:
        enable_cnt = 0;
        try:
            f = open(rules_file,"r")
        except:
            p_debug("%s: Failed to open rules file %s" % (str(whoami()),rules_file))
            sys.exit(1)

        rule_list = f.readlines()
        f.close()
        new_rule_list = []
        for rule in rule_list:
            m = disabled_rule_re.match(rule)
            if m != None:
                subact = m.group('action')
                #print subact
                rule = disabled_rule_re.sub(subact, rule)
                enable_cnt += 1
                #print rule
                new_rule_list.append(rule)
            else:
                new_rule_list.append(rule)

        if enable_cnt > 0:
            try:
                os.rename(rules_file,rules_file + ".orig")
            except:
                p_warn("%s: failed to rename old rules file %s\n" % (str(whoami()),rules_file))

            try:
                f = open(rules_file, 'w')
                f.writelines(new_rule_list)
                f.close()
                #print "%s: rules file %s had %i disabled rules which we enabled. the orginal file is located at %s" % (str(whoami()),rules_file,enable_cnt)
            except:
                p_error("%s: failed to write new uncommented rules file %s" % (str(whoami()),rules_file))
                sys.exit(1)

#http://slacy.com/blog/2010/05/python-multi-dimensional-dicts-using-defaultdict/
def deepDefaultDict():
    return defaultdict(deepDefaultDict)

class recursivedefaultdict(defaultdict):
    def __init__(self):
        self.default_factory = type(self) 

# Uncomment this for testing
if __name__ == "__main__":
    # Add here your tests invocating this script directly
    # Test rule search
    lst = find_sid(123, "aaa*", 1)
    for (fil, lin, rule) in lst:
        print " %s %s %s" % (fil, str(lin), rule)

    lst = find_sid(123, "aaa*", 0)
    for (fil, lin, rule) in lst:
        print " %s %s %s" % (fil, str(lin), rule)

    generate_config("snort", "*", "/opt/snort2841/etc/snort.conf.tpl")
    generate_config("suricata", "*", "/opt/suricata102/etc/suricata.yaml.tpl")
    
