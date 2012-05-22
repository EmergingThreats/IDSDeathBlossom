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

class IDSSignature:
    def __init__(self, signature_options):
        #print str(signature_options)
        self.conf = signature_options


    def extract_sid(self, line):
        isrule = re.compile("^\s*(alert|drop|reject|pass)")
        findsid = re.compile("sid\s*:\s*(?P<sid>\d+)\s*;")
        if isrule.match(line):
            s = findsid.search(line)
            if s:
                return s.group("sid")
        return 0

    def comment_rule_line(self, fil, lin, reason):
        p_debug("Looking at %s(%s) -> Reason: %s" % (fil, lin, reason))
        isrule = re.compile("^\s*(alert|drop|reject|pass)")
        skip = 0
    
        buf = ""
        try:
            orig = open(fil, "r")
        except:
            p_error("Cant open %s for reading. Exiting..." % fil)
            sys.exit(-70)
    
        i = 0
        for line in orig:
            i = i + 1
            if int(i) == int(lin):
                if isrule.match(line):
                    p_info("Commenting line on file %s, line %s: %s" % (fil, lin, line))
                    if reason != "":
                        buf = "%s# Commented by idstool, reason: %s -- Orig Signature: #%s" % (buf, reason.rstrip("\n"), line)
                    else:
                        buf = "%s# Commented by idstool -- Orig Signature: #%s" % (buf, line)
                else:
                    p_info("Config warning/error on file %s, line %s: %s" % (fil, lin, line))
                    skip = 1
            else:
                buf = "%s%s" % (buf, line)
        orig.close()

        # after file is closed
        if skip == 1:
            return -1 
    
        try:
            dest = open(fil, "w")
            dest.truncate()
            dest.write(buf)
            dest.close()
        except:
            p_error("Cant open <%s> for writing" % str(fil))
            return 0

        return 1
    

    def get_rule(self, fil, lin):
        p_debug("Opening *%s*" % fil)
        try:
            orig = open(fil, "r")
        except:
            p_error("Cant open %s for reading. Exiting..." % fil)
            sys.exit(-70)
    
        i = 0
        for line in orig:
            i = i + 1
            if int(i) == int(lin):
                return line
    
        return None
    
    def __str__(self):
        return "Signature options: \n%s" %str(self.conf)
