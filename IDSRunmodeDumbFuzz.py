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
from IDSLogging import *
from IDSMail import *
import time

class RunmodeDumbFuzz:

    # Run Editcap and Introduce Errors 
    # TODO: Maybe move this function to the pcap class?
    def run_editcap(self, pcap, err_ratio):
        fuzzed_pcap = "%s/%s-%s" % (self.logdir, time.strftime("%Y-%m-%d-T-%H-%M-%S", time.localtime()),os.path.basename(pcap))
        cmd = "editcap -E %s %s %s" % (err_ratio, pcap, fuzzed_pcap)
        returncode, stderr, stdout, elapsed = cmd_wrapper(cmd, 0)
        if returncode == 0:
            return fuzzed_pcap
        else:
            p_warn("editcap returned with errors")
            return "failed"
                   
    def dumbfuzz(self, pcap):
        fuzzed_pcap = self.run_editcap(pcap, "0.02")
        if fuzzed_pcap != "failed":
            if self.run_ids(fuzzed_pcap, "yes") == 0:
                os.remove(fuzzed_pcap)
                info ("%s: We processed the pcap %s and had a normal exit value moving onto the next" % (str(whoami()), fuzzed_pcap))
            else:
                corefiles = "%s/core,%s/core.*" % (os.curdir,os.curdir)
                core_glob_list = get_glob_list(corefiles)
                if core_glob_list:
                    p_critical("%s: fuzzer had a non-zero exit core files found\n %s" % (str(whoami()),list(core_glob_list)))
                    sys.exit(1)
                else:
                    p_warn("%s: fuzzer had a non-zero exit but no core files found"  % (str(whoami())))
                    sys.exit(1)
        else:
            p_warn("%s: failed to edit pcap %s moving on to the next pcap" % (str(whoami()), pcap))
     
