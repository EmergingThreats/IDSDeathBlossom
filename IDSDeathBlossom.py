#!/usr/bin/python
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
from collections import defaultdict
from optparse import OptionParser
import yaml

from IDSEngine import *
from IDSUtils import *
from IDSMail import *
from IDSToolEnv import *
from IDSLogging import *

if __name__ == "__main__":
    #first things first
    runstart = start = time.time()    

    parser = OptionParser()

    # Now it should not be mandatory options like sanitizeboth, sanitizesuri,
    # sanitizesnort, since we choose the target engines on a list of
    # targets (we just need an opt "sanitize")
    #runmodes_available = "fuzz,comparefast,comparefastxtract,rcomparefast,rcomparefastxtract,run,xtract,verify,sanitize,sidperfq"
    runmodes_available = "dumbfuzz,comparefast,rcomparefast,run,xtract,xtractall,verify,sanitize,sidperfq,reportonly"

    # What else do you want from me?
    parser.add_option("-R","--runmode", dest="runmode", type="string", help="Currently the following runmodes are supported: %s" % runmodes_available)

    #path to config file
    #parser.add_option("-c", "--config", dest="config", default="config/config.yaml", type="string", help="IDSTool config file")
    parser.add_option("-c", "--config", dest="config", type="string", help="IDSTool config file")

    parser.add_option("-t", "--targets", dest="targets", type="string", help="The target engines separated by commas. Use -L to get a list of available engines/profiles. You can also use \"all\" the envines available passing --targets=all")

    parser.add_option("-v", "--verbose-level", dest="log_level", type="string", help="The logging level that you want to use. Must be one of debug, info, warn, error, critical. Default is \"info\"")
    
    #editcap error ratio
    parser.add_option("--eratio", dest="eratio", type="float", help="error ratio for editcap 0.00 - 1.00")
    
    #path to the pcaps we will be chewing on
    parser.add_option("--pcappath", dest="pcappath", type="string", help="path to pcaps we will read from glob format")
    
    #paths to be ignored
    parser.add_option("--pcapignore", dest="pcapignore", type="string", help="glob for pcaps we will ignore")

    #path for storing performance stats
    parser.add_option("--report-group", dest="reportgroup", default="default", type="string", help="Used in conjuction to reportdb. Attach the reports to this reportgroup")
    
    #path to yaml file for verification modes
    parser.add_option("--verifyconf", dest="verifyconf", type="string", help="path to verification yaml file")
    
    #sort pcaps currently only size is supported want to add more such as modified time etc
    parser.add_option("--sortpcaps", dest="sortpcaps", type="string", help="sort pcap list based on a file attribute currently all that is supported is size and random sort")
       
    #if we have a file containing a list of sids that we don't want to extract flows for pass it here 
    parser.add_option("--xtractignore", dest="xtractignore", type="string", help="glob of sigs not to xtract flows for")

    #number of times to loop the test useful for fuzzing infinitely or to compute averages
    parser.add_option("--loopnum", dest="loopnum", type="string", help="number of times to loop the test defaults to one you can also use forever to loop until error defaults to one")

    #path to config file tpl
    parser.add_option("--snortconfigtpl", dest="snortconfigtpl", type="string", help="IDSTool config file template")
    parser.add_option("--suriconfigtpl", dest="suriconfigtpl", type="string", help="IDSTool config file template")

    #glob for rules (used with sanitization)
    parser.add_option("--snortrules", dest="snortrules", type="string", help="rule glob of snort rules, used to grep for certain keyword/values (ex: sanitizing flowbits)")

    parser.add_option("--surirules", dest="surirules", type="string", help="rule glob of suricata rules, used to grep for certain keyword/values (ex: sanitizing flowbits)")
   
    #email on events 
    parser.add_option("--emailon", dest="emailon", type="string", help="email on certain events currently all that is supported is error,TopNWorstAll,TopNWorstCurrent,LoadReportCurrent,sanitize,comparefast,sqlquery")

    #email src
    parser.add_option("--emailsrc", dest="emailsrc", type="string", help="src email address to send from")

    #email dst
    parser.add_option("--emaildst", dest="emaildst", type="string", help="dst email to send to")

    #email server 
    parser.add_option("--emailsrv", dest="emailsrv", type="string", help="email server to send our mail through defaults to localhost")

    #email subject to prepend
    parser.add_option("--emailsubject", dest="emailsubject", type="string", help="")

    #look for errors in stdout/stderr
    parser.add_option("--parseout", dest="parseout", type="string", help="Parse stderr/stdout looking for errors and warnings and report them.")

    #error on warning. Treat warnings as errors everywhere
    parser.add_option("--warnaserror", dest="warnaserror", type="string", help="treat warnings like errors")
    
    #list of things to generate reports on.
    parser.add_option("--reporton", dest="reporton", type="string", help="list of events to report on options are ids,ruleperf,idsperf,fpblacklist,TopNWorstAll,TopNWorstCurrent,LoadReportCurrent")

    #number of things to report on for topN thingies.
    parser.add_option("--topN", dest="topN", type="string", default=10, help="number of events to return for topN reports defaults to 50")
    
    #global log directory for reporting etc.
    parser.add_option("--globallogdir", dest="globallogdir", help="shared global log directory for reports etc if IDS specific log dirs not specified this will be used")    

    #custom query to the db
    parser.add_option("--sqlquery", dest="sqlquery", help="Query to execute in the db specified with perfdb")

    #append and create run-id to log directories?
    parser.add_option("--appendrunid", dest="appendrunid", action="store_true", default = False, help="append the run-id to the log dir's will create and store logs in logdir/runmode-timestamp format")

    #append and create engine to log directories?
    parser.add_option("--appendengineid", dest="appendengineid", action="store_true", default = False, help="append the engine to the log dir's will create and store logs in logdir/engineid format")

    #append and create engine to log directories?
    parser.add_option("--glogoverride", dest="glogoverride", action="store_true", default = False, help="Override the engine specific log dirs with the global log dir")
    
    #comparefast runmode options
    parser.add_option("--cmpropts", dest="cmpropts", help="pass options for comparefast runmode in format file1:mode1,file2:mode2")

    #the sid we want to pull perf stats on via the sidperfq runmode
    parser.add_option("--sperfsid", dest="sperfsid", help="sid to pull perf info for, should be used in conjunciton with the sidperfq rumode")

    #the sid we want to pull perf stats on via the sidperfq runmode
    parser.add_option("--enableallrules", dest="enableallrules", help="Enable all rules for given globlist")

    # We need templates for this option
    parser.add_option("--use-custom-rules", dest="usecustomrules", action="store_true", default = False, help="This option need template configs for genererating config files to include only the rulefiles specified by")

    # validators
    parser.add_option("--use-snortvalidator", dest="usesnortvalidator", action="store_true", default = False, help="Use snort validator (This option should be used only with the runmode \sanitize\"). It will add snortvalidator reports to the email reports. This option is only compatible with snort 2.8.4*")
    parser.add_option("--use-dumbpig", dest="usedumbpig", action="store_true", default = False, help="Use snort validator (This option should be used only with the runmode \sanitize\"). It will add dumbpig reports to the email reports. This option is only compatible with snort 2.8.4*")

    #Custom setting for engines:
    parser.add_option("--target-opts", dest="target-opts", help="To specify custom values use the following synthaxs: \n< enginename1 | all> : varname1=varval1 , varname2=varval2 , ... [; < enginename2 | all> : varname1=varval1 , varname2=varval2 , ...[...]]   \nExample: --target-opts=\"snort2861open:config=/path/to/conf;suricata102open:path=/path/to/suribin,config=/path/to/config;all:logdir=/path/to/logdir/\"\nThat will modify the config file path of snort2861open, suricata102open, the path to bin of suricata, and the log dir of all the engines available. To list the engines available use -L. The list of variables that you can set are: 'enable', 'fastlog', 'summary', 'version', 'logdir', 'path', 'config', 'configtpl', 'customrules'")

    #Custom setting for engines:
    parser.add_option("-L", "--list-engines", action="store_true", dest="list_engines", default = False, help="List the config of available engines")

    #fast pattern black list checking
    parser.add_option("--fpblacklistopts", dest="fpblacklistopts", help="format is <path to blacklist file:(case|nocase):optional rulesglob>")

    #Use a custom runid
    parser.add_option("--custom-runid", dest="custom_runid", help="Custom runid instead of runmode-datestamp format")

    # Parsed config
    (options, args) = parser.parse_args()
    #print str(options)
    if options == []:
        print parser.print_help()
        sys.exit(-1)

    if not options.config or options.config == "":
        print ("You must specify a config file. Please, use -c or --config option")
        print parser.print_help()
        sys.exit(-1)

    try:
        f = open(options.config)
        confmap = yaml.load(f)
        f.close()
    except:
        print "Error. Config file not found. Exiting now."
        sys.exit(-15)

    overrideOption(confmap["runmode_options"], options.__dict__,"globallogdir")
    logLevel=''
    logFilename=''
    try:
        logLevel = confmap['log_level']
        logFilename = confmap['log_filename']
    except:
        logLevel = 'info'
        logFilename = "%s/IDSDeathBlossom.py.log" % (confmap["runmode_options"]["globallogdir"])

    if not logLevel:
        logLevel= "info"

    SetLogLevel(logLevel)

    if not logFilename:
        logFilename= "%s/IDSDeathBlossom.py.log" % (confmap["runmode_options"]["globallogdir"]) 
    SetLogFilename(logFilename)

    # Override log_level from config if we have a log level from cli
    if options.log_level and options.log_level != "":
        SetLogLevel(options.log_level)

    LogInit()

    IDSTool = IDSToolEnv(confmap)
    engines_available = ""
    for engine in IDSTool.EngineMgr.engines.keys():
        if engines_available != "":
            engines_available = "%s,%s" % (engines_available, engine)
        else:
            engines_available = "%s" % engine

    if options.list_engines == True:
        p_info("The following engines are available: %s" % engines_available)
        print IDSTool.EngineMgr
        sys.exit(0)

    if not options.runmode or options.runmode not in runmodes_available.split(','):
        print "Runmode not available or missing, runmodes available %s" % runmodes_available

    # Check that we have the specified targets
    if not options.targets:
        p_warn("No target engine specified, to view more details of them, please, use the option -L")

    IDSTool.targets = []
    if options.targets and options.targets != "":
        if "all" in options.targets.replace(' ','').split(','):
            IDSTool.targets = engines_available.replace(' ','').split(',')
        else:
            for target in options.targets.replace(' ','').split(','):
                if target not in engines_available.replace(' ','').split(','):
                    p_error("Target not available (%s), choose one of %s. To view more details of them, please, use the option -L" % (options.targets, engines_available))
                    print parser.print_help()
                    sys.exit(-3)
                else:
                    IDSTool.targets.append(target)
    
    p_info("Runmode set to %s" % options.runmode)
    p_info("Targets set to %s" % str(options.targets))

    # Override config with cli options if any
    options = IDSTool.setCliOpts(options)
    IDSTool.options = options

    IDSTool.Runmode.runmode = options.runmode

    # Let the engines have the scope of other settings
    for e in IDSTool.EngineMgr.engines.values():
        if e.conf["engine"] in IDSTool.targets:
            e.Mail = IDSTool.Mail
            e.Pcap = IDSTool.Pcap
            e.Signature = IDSTool.Signature
            e.Runmode = IDSTool.Runmode
            e.Editcap = IDSTool.Editcap
            if IDSTool.__dict__.has_key("perfdb") and IDSTool.perfdb:
                e.db = IDSTool.db
            else:
                e.c = None
            e.setDefaults()


    IDSTool.run()

    runstop = time.time() - runstart

    p_info("Total time for the idstool %s" % runstop)
    sys.exit(0)


'''
#print str(IDSTool)
# We can access to the data of an specific engine like this:
#    IDSTool.Mail.sendEmail("Testing", "hi you!", [], "pablo.rincon.crespo@gmail.com")
# print EngineMgr.engines['suricata102']
# print str(EngineMgr)
'''

