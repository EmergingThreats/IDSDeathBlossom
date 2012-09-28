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
import struct
import socket

class RunmodeExtractAll:
    def xtractall_fast(self,fastlog):
        try:
            #open the alert file and iterate the lines looking for log lines with gid of 1 capture src,dst sport,dport
            f = open(fastlog)
        except:
            p_error("xtractall_fast: failed to open alert fast file: " + fastlog)
            sys.exit(1)    
        else:
            p_info("xtractall_fast: parsing alert fast file: " + fastlog)
                
        for line in f.readlines():
            #we are only looking for gid's of 1 as we don't care about preproc generated events
            m = self.regex["afast"].match(line)
            
            if m != None:
                #if we don't already have an entry in the dict for the sid enter it now
                proto = m.group('proto')
                if proto:
                    tmpdict = {}
                    cproto = ""
                    #print "proto is: " + proto
                    #print m.groups()
                    if proto == "UDP" or proto == "TCP" or proto == "6" or proto == "17":
                        tmpdict['src'] = m.group('src')
                        tmpdict['sport'] = int(m.group('sport'))
                        tmpdict['dst'] = m.group('dst')
                        tmpdict['dport'] = int(m.group('dport'))
                        #convert as suricata currently always prints proto numbers
                        if proto == "UDP" or proto == "17":
                            tmpdict['cproto'] = "udp"
                            tmpdict['nproto'] = 17
                        elif proto == "TCP" or proto == "6":
                            tmpdict['cproto'] = "tcp"
                            tmpdict['nproto'] = 6
                        tmpdict['bpffilter'] = "host %s and port %s and host %s and port %s and %s" % (tmpdict['src'], tmpdict['sport'], tmpdict['dst'], tmpdict['dport'], tmpdict['cproto'])
                        tmpdict['hash'] = tmpdict['nproto'] + struct.unpack('!L',socket.inet_aton(tmpdict['src']))[0] + tmpdict['sport'] + struct.unpack('!L',socket.inet_aton(tmpdict['dst']))[0] + tmpdict['dport']
                    elif proto == "ICMP" or proto == "1":
                        tmpdict['src'] = m.group('src')
                        tmpdict['dst'] = m.group('dst')
                        #convert as suricata always prints proto numbers
                        tmpdict['cproto'] = "icmp"
                        tmpdict['nproto'] = 1
                        tmpdict['bpffilter'] = "host %s and host %s and %s" % (tmpdict['src'], tmpdict['dst'], tmpdict['cproto'])
                        tmpdict['hash'] = tmpdict['nproto'] + struct.unpack('!L',socket.inet_aton(tmpdict['src']))[0] + struct.unpack('!L',socket.inet_aton(tmpdict['dst']))[0]
                    elif re.search("^PROTO\:\d+", proto):
                        #split PROTO:\d
                        protsplit = re.split(r"(\:)", proto)
                        #tcpdump doesn't like the leading 0 on the proto num
                        protfinal = re.sub(r"^0", '', protsplit[2])
                        src = m.group('src')
                        dst = m.group('dst')
                        tmpdict['src'] = m.group('src')
                        tmpdict['dst'] = m.group('dst')
                        tmpdict['cproto'] = protfinal
                        tmpdict['nproto'] = protfinal
                        tmpdict['bpffilter'] = "host %s and host %s and %s" % (tmpdict['src'], tmpdict['dst'], tmpdict['cproto'])
                        tmpdict['hash'] = tmpdict['nproto'] + struct.unpack('!L',socket.inet_aton(tmpdict['src']))[0] + struct.unpack('!L',socket.inet_aton(tmpdict['dst']))[0]
                    #for suricata fast log currently not formated properly
                    elif re.search("^\d+$", proto):
                        protfinal = re.sub(r"^0", '', proto)
                        src = m.group('src')
                        dst = m.group('dst')
                        tmpdict['src'] = m.group('src')
                        tmpdict['dst'] = m.group('dst')
                        tmpdict['cproto'] = protfinal
                        tmpdict['nproto'] = protfinal
                        tmpdict['bpffilter'] = "host %s and host %s and %s" % (tmpdict['src'], tmpdict['dst'], tmpdict['cproto'])
                        tmpdict['hash'] = tmpdict['nproto'] + struct.unpack('!L',socket.inet_aton(tmpdict['src']))[0] + struct.unpack('!L',socket.inet_aton(tmpdict['dst']))[0]

                    if self.alerthash.has_key(tmpdict['hash']):
                        if m.group('sid') not in self.alerthash[tmpdict['hash']]['sids']:
                            self.alerthash[tmpdict['hash']]['sids'].append(m.group('sid'))
                    else:
                        self.alerthash[tmpdict['hash']] =  copy.deepcopy(tmpdict)
                        self.alerthash[tmpdict['hash']]['sids']=[] 
                        self.alerthash[tmpdict['hash']]['sids'].append(m.group('sid'))

                else:
                    p_info("invalid proto:")
                    p_info(line)
                    p_info(m.groups())
            else:
                p_info("error matching regex for the following line\n" + line)

    #extract based on the flow
    # TODO: Maybe move this function to the pcap class?
    def run_xa_tcpdump(self, bpffilter, pcap, out):
        cmd = "tcpdump -n -r %s -w %s%s %s" % (pcap, self.Runmode.conf["globallogdir"], out, bpffilter)
        returncode, stderr, stdout, elapsed = cmd_wrapper(cmd, 0)
        if returncode == 0:
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
    def xtractall(self, pcap):
        self.alerthash ={}
        if self.run_ids(pcap, "yes") == 0:
            if os.path.exists(self.newfastlog):
                self.xtractall_fast(self.newfastlog)
            for entry in self.alerthash:
                print entry
                sidlist = '-'.join(map(str,self.alerthash[entry]['sids']))
                out = "%s-proto-%s-s-%s-sport-%s-d-%s-dport-%s-sids-%s.pcap" % (os.path.basename(pcap),self.alerthash[entry]['cproto'], self.alerthash[entry]['src'], self.alerthash[entry]['sport'],self.alerthash[entry]['dst'],self.alerthash[entry]['dport'],sidlist)
                self.run_xa_tcpdump(self.alerthash[entry]['bpffilter'], pcap ,out)

    #given a pcap and a fast log extract flows
    def xtractallfast(self,pcap,fastlog):
        if os.path.exists(fastlog) and os.path.exists(pcap):
            self.xtractall_fast(fastlog)
        else:
            p_warn("%s: could not find user provided fastlog %s or pcap %s" % (fastlog,pcap))
            for entry in self.alerthash:
                print entry
                sidlist = '-'.join(map(str,self.alerthash[entry]['sids']))
                out = "%s-proto-%s-s-%s-sport-%s-d-%s-dport-%s-sids-%s.pcap" % (os.path.basename(pcap),self.alerthash[entry]['cproto'], self.alerthash[entry]['src'], self.alerthash[entry]['sport'],self.alerthash[entry]['dst'],self.alerthash[entry]['dport'],sidlist)
                self.run_xa_tcpdump(self.alerthash[entry]['bpffilter'], pcap ,out)
 
