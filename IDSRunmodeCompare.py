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

from IDSLogging import *
from IDSUtils import *
from IDSMail import *
import time


class RunmodeCompare:
    #globlist of pcaps to ignore
    def parse_xtract_ignore(self):
        xignore = []

        f = open(self.Signature.conf["xtractignore"])
        for line in f.readlines():
            m = re.match(r"^\d+$", line)
            if m != None:
                line = line.rstrip('\n')
                xignore.append(line)
            else:
                p_warn("%s: %s does not appear to be a valid sid" % (str(whoami()), line))
                   
        p_info("ignoring the following sids")
        p_info(xignore)

        return xignore


    #parse a fast log and store in a dict 
    def parse_fast(self, alertdict, newfastlog, mode):
        try:
            #open the alert file and iterate the lines looking for log lines with gid of 1 capture src,dst sport,dport
            f = open(newfastlog)
        except:
            p_error("compare_parse_fast: failed to open alert fast file: " + newfastlog)
            sys.exit(1) 
        else:
            p_debug("compare_parse_fast: parsing alert fast file: " + newfastlog)

        for line in f.readlines():
            #we are only looking for gid's of 1 as we don't care about preproc generated events
            m = self.regex["afast"].match(line)
            if m != None:
                sid = m.group('sid')
                if alertdict.has_key(sid):
                    #print "adding %s:%s" % (mode, sid)
                    if alertdict[sid].has_key(mode): 
                        alertdict[sid][mode] += 1
                    else:
                        alertdict[sid][mode] = 1
                else:
                    alertdict[sid][mode] = 1
            #else:
                #print "%s: nonmatching fast log \n %s" % (str(whoami()), line)  





    #run suricata and snort and compare the results
    def rcomparefast(self, pcap):
            alertdict = recursivedefaultdict()
            es1,es2 = self.targets[0:2]
            e1 = self.EngineMgr.engines[es1]
            e2 = self.EngineMgr.engines[es2]
            if e1.run_ids(pcap, "no") == 0:
                    if os.path.exists(e1.newfastlog):
                        self.parse_fast(alertdict, e1.newfastlog, e1.engine)
                    else:
                       p_error("%s: failed to find alert log file %s\n" % (str(whoami()), str(e1.newfastlog)))
                       sys.exit(1) 

            if e2.run_ids(pcap, "no") == 0:
                    if os.path.exists(e2.newfastlog):
                        self.parse_fast(alertdict, e2.newfastlog, e2.engine)
                    else:
                       p_error("%s: failed to find alert log file %s\n" % (str(whoami()), str(e2.newfastlog)))
                       sys.exit(1)
            output = "%s/rcomparefast-%s-%s.txt" % (str(e1.conf["logdir"]), str(os.path.basename(pcap)), str(e2.currentts))
            self.compare_fast(alertdict, e1.engine, e2.engine, output)

    def comparefast(self,compareoptions):
            file1 = ""
            mode1 = ""
            file2 = ""
            mode2 = ""

            m = self.regex["cmpropts"].match(compareoptions)
            if m:
                file1 = m.group('file1')
                mode1 = m.group('mode1')
                file2 = m.group('file2')
                mode2 = m.group('mode2')
            else:
                p_error("%s: failed to parse alert fast comparison options should be in the format file1:mode1,file2:mode2 you provided %s\n" % (str(whoami()),compareoptions))
                sys.exit(1)

            alertdict = recursivedefaultdict()
            if os.path.exists(file1):
                self.parse_fast(alertdict, file1, mode1)
            else:
                 p_error("%s: failed to find alert log file %s\n" % (str(whoami()), str(file1)))
                 sys.exit(1)

            if os.path.exists(file2):
                self.parse_fast(alertdict, file2, mode2)
            else:
                p_error("%s: failed to find alert log file %s\n" % (str(whoami()), str(file2)))
                sys.exit(1)

            output = "%s/comparefast-%s-%s-%s.txt" % (str(self.Runmode.conf["globallogdir"]), mode1, mode2, time.strftime("%Y-%m-%d-T-%H-%M-%S", time.localtime()))
            self.compare_fast(alertdict, mode1, mode2, output)

    #compare a dict containing the output from parse_fast
    def compare_fast(self, alertdict, mode1, mode2, output):
        mode1missed = 0
        mode2missed = 0
        mode1morethan2 = 0
        mode2morethan1 = 0
        
        #break out the lines by missed event type
        mode1missedarr = []
        mode2missedarr = []
        mode1morethan2arr = []
        mode2morethan1arr = []
 
        #alert totals
        mode1total = 0
        mode2total = 0
        try:
            #open the alert file and iterate the lines looking for log lines with gid of 1 capture src,dst sport,dport
            out = open(output, 'w')
        except:
            p_error("compare_fast: failed to open the output file: " + output)
            sys.exit(1) 
        else:
            p_info("compare_fast: comparing snort and suricata alerts writing output to: " + output)
        for (sid, value) in alertdict.iteritems():
            #print alertdict[sid]
            if alertdict[sid].has_key(mode1) or alertdict[sid].has_key(mode2):
                #mode2 missed detection
                if alertdict[sid].has_key(mode1) and not alertdict[sid].has_key(mode2):
                    mode2missedarr.append('%s missed detection sid:%s %s:%s %s:None\n' % (mode2, sid, mode1, alertdict[sid][mode1], mode2))
                    mode2missed += alertdict[sid][mode1]
                    mode1total += alertdict[sid][mode1]
                #mode1 missed detection
                elif alertdict[sid].has_key(mode2) and not alertdict[sid].has_key(mode1):
                    mode1missedarr.append('%s missed detection sid:%s %s:None %s:%s\n' % (mode1, sid, mode1, mode2, alertdict[sid][mode2]))
                    mode1missed += alertdict[sid][mode2]
                    mode2total += alertdict[sid][mode2]
                #mode1 alerted more times than mode2
                elif alertdict[sid][mode1] > alertdict[sid][mode2]:
                    mode1morethan2arr.append('%s alerted more times than %s sid:%s %s:%s %s:%s diff:%i\n' % (mode1, mode2, sid, mode1, alertdict[sid][mode1], mode2, alertdict[sid][mode2],(alertdict[sid][mode1] - alertdict[sid][mode2])))
                    mode1morethan2 += (alertdict[sid][mode1] - alertdict[sid][mode2])
                    mode1total += alertdict[sid][mode1]
                    mode2total += alertdict[sid][mode2]
                #suricata alerted more times than snort
                elif alertdict[sid][mode2] > alertdict[sid][mode1]:
                    mode2morethan1arr.append('%s alerted more times than %s sid:%s %s:%s %s:%s diff:%i\n' % (mode2, mode1, sid, mode1, alertdict[sid][mode1], mode2, alertdict[sid][mode2],(alertdict[sid][mode2] - alertdict[sid][mode1])))
                    mode2morethan1 += (alertdict[sid][mode2] - alertdict[sid][mode1])
                    mode1total += alertdict[sid][mode1]
                    mode2total += alertdict[sid][mode2]
                elif alertdict[sid][mode2] == alertdict[sid][mode1]:
                    mode1total += alertdict[sid][mode1]
                    mode2total += alertdict[sid][mode2]

        out.write("Summary:\n\n")
        out.write('%s total alerts %s\n' % (mode1,mode1total))
        out.write('%s total alerts %s\n' % (mode2,mode2total))
        out.write('%s missed cnt:%s\n%s missed cnt:%s\n%s more than %s cnt:%s\n%s more than %s cnt:%s\n' % (mode2, mode2missed, mode1, mode1missed, mode1, mode2,  mode1morethan2, mode2, mode1, mode2morethan1))
        out.write("=================================================\n")

        out.write("%s missed detection:\n\n" % mode1)
        for line in mode1missedarr:
            out.write(line)
        out.write("=================================================\n")

        out.write("%s missed detection:\n\n" % mode2)
        for line in mode2missedarr:
            out.write(line)
        out.write("=================================================\n")

        out.write("%s alerted more than %s:\n\n" % (mode1,mode2))
        for line in mode1morethan2arr:
            out.write(line)
        out.write("=================================================\n")

        out.write("%s alerted more than %s:\n\n" % (mode2,mode1))
        for line in mode2morethan1arr:
            out.write(line)
        out.write("=================================================\n")

        out.close()

        if "comparefast" in self.Runmode.conf["emailonarr"]:
            filearr=[output]
            #send_email(self.Mail.conf["emailsrc"], self.Mail.conf["emaildst"], str(self.Mail.conf["emailsubject"]) + "Alert Fast Compare " + mode1 + " vs. " + mode2, None, self.Mail.conf["emailsrv"], filearr)
            # Better use this one:
            self.Mail.sendEmail("Alert Fast Compare " + mode1 + " vs. " + mode2, None, filearr)



