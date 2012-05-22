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

from IDSUtils import *
from IDSMail import *
from IDSSignature import *
import time
from IDSLogging import *
from IDSReport import *

class RunmodeSanitize:
    def dumpErrWarnToDict(self):
        for w in self.rule_warnings:
            self.drule_warnings[w] = 1
        for e in self.rule_errors:
            self.drule_errors[e] = 1

    def dumpDictToErrWarn(self):
        self.rule_errors = []
        self.rule_warnings = []

        for w in self.drule_warnings:
            self.rule_warnings.append(w)
        for e in self.drule_errors:
            self.rule_errors.append(e)

    #Sanitize signatures (comment them out)
    def sanitize(self):
        limit = 20
        self.rule_warnings = []
        self.rule_errors = []

        self.drule_warnings = {}
        self.drule_errors = {}

        self.reportonsanitize = 1
        self.emailsubject = " Sanitization Summary Report"
        # Build custom subject with the prefix (we should change the name)
        self.currentts = time.strftime("%Y-%m-%d-T-%H-%M-%S", time.localtime())
        self.ts = str(int(time.time()))
        self.resultPath = self.Runmode.conf["globallogdir"] + "/RunmodeSanitize/" + self.conf['engine'] + "/Sanitization_Summary_Report%s" % self.Mail.conf['emailsubject'].replace("/","").replace(" ", "_").replace("[","_").replace("]","_") + "/" + self.currentts + "/" 
        if not os.path.exists(self.resultPath):
            try:
               os.makedirs(self.resultPath)
            except:
               p_error("%s: failed to make directory %s\n" % (str(whoami()),e.conf["logdir"]))
               sys.exit(1)

        print "ReportPath: %s" % self.resultPath
        self.ALL_RULES_LOADED_SNORT = "Snort sucessfully loaded all rules and checked all rule chains"
        self.ALL_RULES_LOADED_SURICATA = " rules succesfully loaded, 0 rules failed"
        flag_all_rules = 0
        # for sanity reasons, to avoid infinite loops
        flag_err_or_warn = 1
        files = []

        self.pcapfile = self.Pcap.gen_dummy_pcap()
        p_debug("Initializing Sanitization for %s" % self.conf['engine'])

        r = IDSReport(self.conf['engine'] + " " + self.emailsubject + " " + self.currentts, self.conf)
        r.storeReport((self.Runmode.conf['reportgroup'], self.ts, "Running", self.engine, "", "", 0, 0, 0, 0), self.r, "sanitize") 

        r.addHeader({"Engine" : self.conf['engine'], "Time" : self.currentts})

        #if we supply a rulesglob and our rules list comes up empty bail
        if self.conf.has_key("customrules") and self.Runmode.conf.has_key("usecustomrules") and self.Runmode.conf["usecustomrules"]:
           if get_glob_list(self.conf["customrules"]) == []:
               p_error("%s: rulesglob %s was supplied and it returned an empty list. No rules to sanitize bailing" % (str(whoami()),self.conf["customrules"]))
               sys.exit(1)

           r.addHeader({"CustomRules" : get_glob_list(self.conf["customrules"])})

        # If dumbpig is specified, look at version, and generate a report for the rule glob expr
        if self.Runmode.conf.has_key("usedumbpig") and self.Runmode.conf["usedumbpig"] != "" and self.conf.has_key("customrules"):
            p_debug("Using dumbpig")
            r.addHeader("Using dumbpig")
            # ok, go
            rulelist = get_glob_list(self.conf["customrules"])
            if get_glob_list(self.conf["customrules"]) == []:
                p_error("%s: rulesglob %s was supplied and it returned an empty list. No rules to test with dumbpig" % (str(whoami()),self.conf["customrules"]))
                sys.exit(1)
            dumbpigreport = "%s/dumbpig.txt" % self.resultPath
            r.addHeader({"dumbpigreport" : dumbpigreport})
            r.addHeader({"link_dumbpigreport" : "dumbpig.txt"})
            out = ''
            for f in rulelist:
                cmd = 'dumbpig.pl -r %s -s 3|egrep "^Issue [0-9]+| found with rule on line |^Rule source sid: [0-9]+|^- "|awk \'BEGIN{i=0; sid="";fil="";}/Issue/{if (i >= 1){ for(i in problems){printf "%%s; %%s; %%s", sid, fil, problems[i]; delete problems[i];};print "";};sid=""; i=0;}/ found with rule on line /{fil=$0;}/Rule source sid:/{sid=$0;}/This rule looks more suited to a firewall or blacklist|IP rule without a content match. Put this in a firewall/{next;}/^- /{problems[i++]=$0;}END{if (i >= 1){ for(i in problems){printf "%%s; %%s; %%s", sid, fil, problems[i]; delete problems[i];};print "";};sid=""; i=0;}\' |grep -v "leon.ward@sourcefire.com" 2>&1 |sort -k4 -n' % f
                self.returncode, self.stderr, self.stdout, self.elapsed = cmd_wrapper(cmd, 1)
                (errors, warnings) = self.parse_dumbpig_out(self.stderr,self.stdout)

                out = "%s******\n%s returncode:%s\noutput:\n%s" %  (out, f, str(self.returncode), self.stdout)
            try:
                srep = open(dumbpigreport, "w")
                srep.write(out)
            except:
                p_error("Could not open %s for rule sanitize report" % dumbpigreport)
                sys.exit(-121)
            srep.close()
            files.append(dumbpigreport)

            self.dumpErrWarnToDict()
            for (fil,lin,rea) in self.rule_errors:
                commentedsid = self.Signature.extract_sid(self.Signature.get_rule(fil, lin))
                if commentedsid:
                    r.addFooter({"link_proback_rule_sid_%s" % str(commentedsid) : "https://proback.emergingthreatspro.com/active/ruleview?rule_id=%s" % str(commentedsid)})
                    r.addBody("File: %s (Line: %s) -- Rule with errors commented at %s, reason: %s -- Rule: %s" %(fil, lin, self.currentts, rea, self.Signature.get_rule(fil, lin)))
            for (fil,lin,rea) in self.rule_warnings:
                commentedsid = self.Signature.extract_sid(self.Signature.get_rule(fil, lin))
                if commentedsid:
                    r.addFooter({"link_proback_rule_sid_%s" % str(commentedsid) : "https://proback.emergingthreatspro.com/active/ruleview?rule_id=%s" % str(commentedsid)})
                    r.addBody("File: %s (Line: %s) -- Rule with errors commented at %s, reason: %s -- Rule: %s" %(fil, lin, self.currentts, rea, self.Signature.get_rule(fil, lin)))
            self.rule_errors = []
            self.rule_warnings = []
            print str(self.rule_errors)

        # If usesnortvalidator is specified, look at version, and generate a report for the rule glob expr
        if self.Runmode.conf.has_key("usesnortvalidator") and self.Runmode.conf["usesnortvalidator"] and self.conf.has_key("customrules"):
            if self.conf.has_key("syntax_version"):
                version = self.conf["syntax_version"]
            else:
                version = "2.9.0"

            p_debug("Using snortvalidator with version %s" % version)
            r.addHeader("Using snortvalidator with version %s" % version)

            # ok, go
            rulelist = get_glob_list(self.conf["customrules"])
            if get_glob_list(self.conf["customrules"]) == []:
                p_error("%s: rulesglob %s was supplied and it returned an empty list. No rules to test with snortvalidator" % (str(whoami()),self.conf["customrules"]))
                sys.exit(1)
            snortvalidatorreport = "%s/snortvalidator.txt" % self.resultPath
            r.addHeader({"snortvalidatorreport" : snortvalidatorreport})
            r.addHeader({"link_snortvalidatorreport" : "snortvalidator.txt"})
            out = ''
            for f in rulelist:
                cmd = "/usr/bin/snortvalidator.pl -t %s -s %s " % (version,f)
                self.returncode, self.stderr, self.stdout, self.elapsed = cmd_wrapper(cmd, 1)
                out = "%s******\n%s returncode:%s\nSTDOUT:\n%s" %  (out, f, str(self.returncode), self.stdout)
                out = "%s******\n%s returncode:%s\nSTDERR:\n%s" %  (out, f, str(self.returncode), self.stderr)
            try:
                srep = open(snortvalidatorreport, "w")
                srep.write(out)
            except:
                p_error("Could not open %s for rule sanitize report" % snortvalidatorreport)
                sys.exit(-121)
            srep.close()
            files.append(snortvalidatorreport)

        #print self
        sreport = "%s/sanitization-old-format.txt" % self.resultPath
        try:
            report=open(sreport,"w")
        except:
            p_error("Error opening %s for writting" % sreport)
            sys.exit(-123)
        sanity_errors = ""
        sanity_warnings = ""
        commented = 0
        ret = 1
        stop = 0

        while flag_all_rules == 0 and flag_err_or_warn == 1 and stop == 0:
            limit = limit - 1
            if limit == 0:
                stop = 1
            # return code is also stored at self.returncode in the engine
            returncode = self.execute("sanitize", self.pcapfile)

            # If we have a segv bail
            if returncode == 139:
                report.write("%s Segmentation Fault Detected bailing" % (self.engine))
                r.addBody("%s Segmentation Fault Detected bailing" % (self.engine))
                stop = 1
            #look for errors and warnings in output with whatever self.returncode val
            (errors, warnings) = self.parse_ids_out(self.stderr,self.stdout)
            self.dumpErrWarnToDict()
            if self.rule_errors == [] and self.rule_warnings == []:
                flag_err_or_warn = 0
                if re.match(r"2(\.8\.6|\.9)",self.conf["version"]) and "fpblacklist" in self.Runmode.conf["reportonarr"]:
                    fpreport = fast_pattern_blacklist((self.stderr+self.stdout),self.Runmode.conf["fpblacklist"],self.Runmode.conf["fpcase"],self.conf["customrules"],self.resultPath)
                    files.append(fpreport)
                    r.addHeader({"fastpatternreport" : fpreport})
                    r.addHeader({"link_fastpatternreport" : "fast-pattern-blacklist-report.txt"})
            else:
                if self.rule_errors != []:
                    p_info("Sanitizing errors")
                    for (fil, line, log) in self.rule_errors:
                        sanity_errors = "%s%s" % (sanity_errors, "File: %s (Line: %s) -- Rule with errors commented at %s, reason: %s --\nRule: %s\n" %(fil, line, self.currentts, log, self.Signature.get_rule(fil, line)))
                        report.write("File: %s (Line: %s) -- Rule with errors commented at %s, reason: %s -- Rule: %s" %(fil, line, self.currentts, log, self.Signature.get_rule(fil, line)))
                        r.addBody("File: %s (Line: %s) -- Rule with errors commented at %s, reason: %s -- Rule: %s" %(fil, line, self.currentts, log, self.Signature.get_rule(fil, line)))
                        commentedsid = self.Signature.extract_sid(self.Signature.get_rule(fil, line))
                        ret = self.Signature.comment_rule_line(fil, line, log)
                        if ret < 1:
                            if ret == -1:
                                p_warn("Uops! Error, this is not a rule. Can't comment out. Check the config of %s ." % self.engine)
                                if returncode != 0:
                                    p_error("Can't continue the sanitization. Reporting and exiting now.")
                                    stop = 1
                            elif ret == 0:
                                p_error("Error, Can't comment out a rule. Check the config and perms of %s ." % self.engine)
                                p_error("Can't continue the sanitization. Reporting and exiting now.")
                                stop = 1
                            else:
                                stop = 1 # (Unknown err)
                        else:
                            commented = commented + 1
                            p_debug("Commented sid %s" % commentedsid)
                            r.addFooter({"link_proback_rule_sid_%s" % str(commentedsid) : "https://proback.emergingthreatspro.com/active/ruleview?rule_id=%s" % str(commentedsid)})
                if self.rule_warnings!= []:
                    p_info("Sanitizing warnings")
                    for (fil, line, log) in self.rule_warnings:
                        sanity_warnings = "%s%s" % (sanity_warnings, "File: %s (Line: %s) -- Rule with errors commented at %s, reason: %s --\nRule: %s\n" %(fil, line, self.currentts, log, self.Signature.get_rule(fil, line)))
                        report.write("File: %s (Line: %s) -- Rule with warnings commented at %s, reason: %s -- Rule: %s" %(fil, line, self.currentts, log, self.Signature.get_rule(fil, line)))
                        r.addBody("File: %s (Line: %s) -- Rule with warnings commented at %s, reason: %s -- Rule: %s" %(fil, line, self.currentts, log, self.Signature.get_rule(fil, line)))
                        commentedsid = self.Signature.extract_sid(self.Signature.get_rule(fil, line))
                        ret = self.Signature.comment_rule_line(fil, line, log)
                        if ret < 1:
                            if ret == -1:
                                p_warn("Uops! Error, this is not a rule. Can't comment out. Check the config of %s ." % self.engine)
                            elif ret == 0:
                                p_error("Error, Can't comment out a rule. Check the config and perms of %s ." % self.engine)
                                p_error("Can't continue the sanitization. Reporting and exiting now.")
                                stop = 1
                            else:
                                stop = 1 # (Unknown err)
                        else:
                            commented = commented + 1
                            p_debug("Commented sid %s" % commentedsid)
                            r.addFooter({"link_proback_rule_sid_%s" % str(commentedsid) : "https://proback.emergingthreatspro.com/active/ruleview?rule_id=%s" % str(commentedsid)})

            for line in self.stdout.split('\n'):
                #Check for the success condition
                m = self.regex["all_rules_loaded"].match(line)
                if m != None or line.find(self.ALL_RULES_LOADED_SNORT) >= 0 or line.find(self.ALL_RULES_LOADED_SURICATA) >= 0:
                    p_info("All rule files sanitized!! Great!!")
                    r.addFooter("All rule files sanitized!! Great!!")
                    flag_all_rules = 1

            for line in self.stderr.split('\n'):
                #Check for the success condition
                m = self.regex["all_rules_loaded"].match(line)
                if m != None or line.find(self.ALL_RULES_LOADED_SNORT) >= 0 or line.find(self.ALL_RULES_LOADED_SURICATA) >= 0:
                    p_info("All rule files sanitized!! Great!!")
                    r.addFooter("All rule files sanitized!! Great!!")
                    flag_all_rules = 1

            if flag_err_or_warn == 0:
                p_info("No more rule warnings/errors to fix")


        self.dumpDictToErrWarn()
        mailbody = "-- Sanitization Summary --\n"
        if ret < 1:
            if ret == -1:
                mailbody = "%sFatal Error! Not a rule error (probably a config error (at file %s, line %s). Can't comment out. Check the config of %s Exiting.\n" % (mailbody, fil, line, self.engine)
                r.addBody("Fatal Error! Not a rule error (probably a config error (at file %s, line %s). Can't comment out. Check the config of %s Exiting." % (fil, line, self.engine))
            if ret == 0:
                mailbody = "%sFatal Error! Can't comment out a rule (at file %s, line %s). Check the config and perms of %s Exiting." % (mailbody, fil, line, self.engine) 
                r.addBody("Fatal Error! Can't comment out a rule (at file %s, line %s). Check the config and perms of %s Exiting." % (fil, line, self.engine))
        # now we should have sanitized the files as much as possible. Let's see
        # the return codes and if we have checked the "all rules loaded" condition
        if not (sanity_errors != "" or  sanity_warnings != "" or self.returncode != 0 or warnings != "" or errors != ""):
            mailbody = "%s[+++] All rules were succesfuly loaded and %s returned no error code" % (mailbody, self.mode)
            r.addFooter("All rules were succesfuly loaded and %s returned no error code" % self.conf["engine"])

        if self.returncode == 0:
            mailbody = "%s[+] %s returned 0 exiting correctly\n" % (mailbody, self.mode)
            r.addFooter("%s returned 0 exiting correctly" % self.conf["engine"])
        else:
            mailbody = "%s[+] %s returned %d not exiting correctly\n" % (mailbody, self.mode, int(self.returncode))
            r.addFooter("%s returned %d exiting correctly" % (self.conf["engine"], int(self.returncode)))

        mailbody = "%s[+] %d rules were commented\n" % (mailbody, commented)
        r.addHeader("%d rules were commented" % commented)
        r.addFooter("%d rules were commented" % commented)

        mailbody = "%s[+] Command executed was %s\n" % (mailbody, self.lastcmd)
        r.addHeader("Command executed: %s" % self.lastcmd)

        if sanity_errors != "":
            mailbody = "%s[+] %s reported errors for the following rules:\n%sQA idstool has commented that rules\n\n" % (mailbody, self.engine, sanity_errors)
            r.addBody({"rule_errors":self.rule_errors})

        if sanity_warnings != "":
            mailbody = "%s[+] %s reported warnings for the following rules:\n%sQA idstool has commented that rules\n\n" % (mailbody, self.engine, sanity_warnings)
            r.addBody({"rule_warnings":self.rule_warnings})

        if errors != "":
            mailbody = "%s[+] %s reported the following errors:\n%s\n" % (mailbody, self.mode, errors)
            r.addBody({"errors":self.errors})

        if warnings != "":
            mailbody = "%s[+] %s reported the following warnings:\n%s\n" % (mailbody, self.mode, warnings)
            r.addBody({"warnings":self.warnings})

        mailbody = "%s*Note: the above error/warning (if any) lists are acummulative across different runs (sanitization runmode call the engine recursively commenting out rules with errors\n)" % mailbody
        r.addBody("*Note: the above error/warning (if any) lists are acummulative across different runs (sanitization runmode call the engine recursively commenting out rules with errors)")

        if flag_err_or_warn == 0:
            mailbody = "%s[+] %s ran without fixable rule errors after sanitizations\n" % (mailbody, self.mode)
            r.addFooter("Engine without fixable rule errors after sanitizations")

        if flag_all_rules == 1:
            mailbody = "%s[+] %s ran loading all rules after this fixes\n" % (mailbody, self.mode)
            r.addFooter("Engine ran loading all rules after sanitizations")

        mailbody = mailbody + "\n-- End of Summary -- \n"

        fo=open(self.resultPath + "stdout.txt","w")
        fo.write(self.stdout)
        fo.close()

        fe=open(self.resultPath + "stderr.txt","w")
        fe.write(self.stderr)
        fe.close()

        r.addHeader({"link_stdout" : "stdout.txt"})
        r.addHeader({"link_stderr" : "stderr.txt"})

        #print mailbody
        reportdata = r.build("raw")
        reportdata = reportdata + "\nRaw Python data:\n" + str(r)
        print reportdata
        #print r.build("html")
        r.save(self.resultPath + "report.html", "html")

        if commented == 0:
            rstatus = "OK"
        else:
            rstatus = "ERRORS"
        if self.warncnt > 0:
            rstatus = "WARNINGS"
        if self.errcnt > 0:
            rstatus = "ERRORS"

        # (reportgroup, timestamp, rstatus, engine, path, relpath, errors, warnings, time) = data
        r.updateReport((self.Runmode.conf['reportgroup'], self.ts, rstatus,
self.engine, self.resultPath + "report.html", self.resultPath + "report.html",
self.errcnt, self.warncnt, time.time() - int(self.ts), commented), self.r, "sanitize")

        #print mailbody
        report.write(mailbody)
        report.close()
        files.append(sreport)
        if self.reportonsanitize == 1:
            self.Mail.sendEmail(self.emailsubject, reportdata, files)

        os.remove(self.pcapfile)

    def parse_dumbpig_out(self,stderr,stdout):
        # Set here the format regex
        # Rule source sid: 2012137 ; 1 Problem(s) found with rule on line 44876 of /opt/ruledump/snort-2.8.6/open/all.rules; - TCP, without flow. Considder adding flow to provide better state tracking on this TCP based rule
        dumbpig_err = re.compile(r"^Rule source sid: .* found with rule on line (?P<line>\d+) of (?P<file>[^\s;]+); (?P<reason>.+$)")
        dumbpig_ignore = re.compile(r'')

        for line in stdout.split('\n'):
            #print line
            m = dumbpig_err.match(line)
            if m != None and self.regex["ignore"].match(line) == None:
                p_info("%s: rule problem(s) found in stdout\nfile: %s (line %s)" % (str(whoami()),m.group("file"),m.group("line")))
                self.rule_errors.append((m.group("file"),m.group("line"), m.group("reason")))

        return ("", "")
