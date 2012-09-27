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

class RunmodeExtract:
    def xtract_fast(self,fastlog):
        try:
            #open the alert file and iterate the lines looking for log lines with gid of 1 capture src,dst sport,dport
            f = open(fastlog)
        except:
            p_error("xtract_fast: failed to open alert fast file: " + fastlog)
            sys.exit(1)    
        else:
            p_info("xtract_fast: parsing alert fast file: " + fastlog)
                
        for line in f.readlines():
            #we are only looking for gid's of 1 as we don't care about preproc generated events
            m = self.regex["afast"].match(line)
            if m != None:
                sid = m.group('sid')
                #if we don't already have an entry in the dict for the sid enter it now
                if sid not in self.sidd and sid not in self.xignore:
                    proto = m.group('proto')
                    if proto:
                        cproto = ""
                        #print "proto is: " + proto
                        #print m.groups()
                        if proto == "UDP" or proto == "TCP" or proto == "6" or proto == "17":
                            src = m.group('src')
                            sport = m.group('sport')
                            dst = m.group('dst')
                            dport = m.group('dport')
                            #convert as suricata currently always prints proto numbers
                            if proto == "UDP" or proto == "17":
                                cproto = "udp"
                            elif proto == "TCP" or proto == "6":
                                cproto = "tcp"
                                bpffilter = "host " + src + " and port " + sport + " and host " + dst + " and port " + dport + " and " + cproto.lower()
                                p_info("Added" + sid + ":" + bpffilter)
                                self.sidd[sid] = bpffilter
                        elif proto == "ICMP" or proto == "1":
                            src = m.group('src')
                            dst = m.group('dst')
                            #convert as suricata always prints proto numbers
                            cproto = "icmp"
                            bpffilter = "host " + src + " and host " + dst + " and " + cproto.lower()
                            p_info("Added" + sid + ":" + bpffilter)
                            self.sidd[sid] = bpffilter
                        elif re.search("^PROTO\:\d+", proto):
                            #split PROTO:\d
                            protsplit = re.split(r"(\:)", proto)
                            #tcpdump doesn't like the leading 0 on the proto num
                            protfinal = re.sub(r"^0", '', protsplit[2])
                            src = m.group('src')
                            dst = m.group('dst')
                            bpffilter = "host " + src + " and host " + dst + " and ip proto " + protfinal
                            p_info("Added" + sid + ":" + bpffilter)
                            self.sidd[sid] = bpffilter
                        #for suricata fast log currently not formated properly
                        elif re.search("^\d+$", proto):
                            protfinal = re.sub(r"^0", '', proto)
                            src = m.group('src')
                            dst = m.group('dst')
                            bpffilter = "host " + src + " and host " + dst + " and ip proto " + protfinal
                            p_info("Added" + sid + ":" + bpffilter)
                                            
                    else:
                        p_info("invalid proto:")
                        p_info(line)
                        p_info(m.groups())
            #else:
                #print "flow already stored for sid" + sid
            else:
                p_info("error matching regex for the following line\n" + line)

    #extract based on the flow
    # TODO: Maybe move this function to the pcap class?
    def run_tcpdump(self, sid, bpffilter, pcap):
        cmd = "tcpdump -n -r %s -w %s/%s.pcap %s" % (pcap, self.Runmode.conf["globallogdir"], sid, bpffilter)
        returncode, stderr, stdout, elapsed = cmd_wrapper(cmd, 0)
        if returncode == 0:
            p_info("extraction successful" + sid + ": " + bpffilter)
            return 0
        else:
            p_info("tcpdump ran with errors")
            return 1
                   
    #globlist of pcaps to ignore
    def parse_xtract_ignore(self):
        xignore = []

        f = open(options.xtractignore)
        for line in f.readlines():
            m = re.match(r"^\d+$", line)
            if m != None:
                line = line.rstrip('\n')
                xignore.append(line)
            else:
                p_warn("%s: %s does not appear to be a valid sid\n" % (str(whoami()), line))
                   
        p_info("ignoring the following sids\n")
        p_info(xignore)

        return xignore

    #given a pcap run the ids and extract flows
    def xtract(self, pcap):
        if self.run_ids(pcap, "yes") == 0:
            if os.path.exists(self.newfastlog):
                self.xtract_fast(self.newfastlog)
            for sid, bpffilter in self.sidd.iteritems():
                self.run_tcpdump(sid, bpffilter, pcap)
                if not sid in self.xignore:
                    self.xignore.append(sid)

    #given a pcap and a fast log extract flows
    def xtractfast(self,pcap,fastlog):
        if os.path.exists(fastlog) and os.path.exists(pcap):
            self.xtract_fast(fastlog)
        else:
            p_warn("%s: could not find user provided fastlog %s or pcap %s" % (fastlog,pcap))
        for sid, bpffilter in self.sidd.iteritems():
            self.run_tcpdump(sid, bpffilter, pcap)
            if not sid in self.xignore:
                self.xignore.append(sid)
    

