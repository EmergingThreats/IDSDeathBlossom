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
import time
from IDSRunmodeCompare import *
from IDSLogging import *

class RunmodeVerify:
    #Given a list of pcaps and sids that we should see fire, validate.
    #TODO: auto-generate this list from the other modes
    #TODO: Support counts for events something like foo.pcap: [2999:10,433:2,1563:1]                        
    def verify(self):
        import yaml
        failcnt = 0
        successcnt = 0
        resultsdict = {}
            
        #there is an inheritence problem here this is a nasty hack to set and unset self.fast.log 
        #newfastlogorig = self.newfastlog
        #perflogorig = self.perflog

        f = open(self.Runmode.conf["verifyconf"])
        try:
            pcapMap = yaml.load(f)
        except:
            p_error("%s:Verify yaml conf mapping failed %s" % (str(whoami()), self.Runmode.conf["verifyconf"]))
            sys.exit(-10)
        f.close()
        
        for key in pcapMap['pcaps']:
             pcap = "%s/%s" % (pcapMap['pcapdir'], key)
             alertdict = self.deepDefaultDict()

             #for a perl programmer used to HoH's multi-dimensional dicts are very frustrating.  Here we store a list because simply checking against a value using a 
             #multi-dimensinonal dict creates a key? wtf? FIXME
             alertlist = []
             if os.path.isfile(pcap):
                 resultsdict[key] = "PASS"
             else:
                 p_warn("%s:Failed to find file %s\n" % (str(whoami()),pcap))

             if self.run_ids(pcap, "no") == 0:
                 if os.path.exists(self.newfastlog):
                     #self.parse_fast(alertdict, self.newfastlog, self.mode)
                     self.IDSRunmodeCompare.parse_fast(alertdict, self.newfastlog, self.mode)
                     alertlist = alertdict.keys()
                     p_debug(self.newfastlog)
                     p_debug(str(alertlist))
                 else:
                      p_error("%s: failed to find alert log file %s\n" % (str(whoami()), str(self.newfastlog)))
                      sys.exit(-1)
                            
                 for sid in pcapMap['pcaps'][key]:
                     if str(sid) not in alertlist and resultsdict[key] == "PASS":
                         #print "FAIL:sid %s not found in %s" % (sid, str(alertlist))
                         resultsdict[key] = "FAIL:sid %s not found in %s" % (sid, pcap)
                         failcnt += 1

                 self.newfastlog = newfastlogorig
                 self.perflog = perflogorig
                 if resultsdict[key] == "PASS":
                     #print "PASS:sid %s found in %s" % (sid, pcap)
                     successcnt += 1   
             else:
                   resultsdict[key] = "FAIL:IDS failure\n"
                   failcnt += 1

        reportfile = "%s/verify-report-%s.txt" % (self.Runmode.conf["globallogdir"], str(self.currentts))
        report = open(reportfile, 'w')       
        p_info("verify results\n")
        report.write("verify results\n")
        for key,value in resultsdict.iteritems():
            p_info("%s:%s" % (key,value))
            report.write("%s:%s\n" % (key,value))
        p_info("successcnt:%i\n" % successcnt)
        report.write("successcnt:%i\n" % successcnt)
        p_info("failcnt:%i\n" % failcnt)
        report.write("failcnt:%i\n" % failcnt)
        report.close()                

    def verify2(self):
        import yaml
        failcnt = 0
        successcnt = 0
        resultsdict = {}

        #there is an inheritence problem here this is a nasty hack to set and unset self.fast.log
        #if self.newfastlog:
        #    newfastlogorig = self.newfastlog

        #perflogorig = self.perflog

        f = open(self.Runmode.conf["verifyconf"])
        try:
            testMap = yaml.load(f)
        except:
            p_error("%s:Verify yaml conf mapping failed %s" % (str(whoami()), self.Runmode.conf["verifyconf"]))
            sys.exit(-10)
        f.close()

        for testid in testMap:
             pcap = "%s/%s" % (testMap[testid]['pcapdir'],testMap[testid]['pcap'])
             rules = "%s/%s" % (testMap[testid]['ruledir'],testMap[testid]['rulefile'])
             alert_opt_regex = re.compile(r"\s*(?P<sid>\d+)\s*(?P<operator>(=|>=|<=|>|<|\!=))\s*(?P<count>\d+)\s*")
             #parse_fast will return [sid][mode]
             alertdict = recursivedefaultdict()
             resultsdict[testid] = "PASS"
             #for a perl programmer used to HoH's multi-dimensional dicts are very frustrating.  Here we store a list because simply checking against a value using a 
             #multi-dimensinonal dict creates a key? wtf? FIXME
             if not os.path.isfile(pcap) and not os.path.isfile(rules):
                 resultsdict[testid] = "FAIL"
                 p_info("FAIL:Failed to find pcap:%s or rules file:%\n" % (pcap,rules))
                 failcnt += 1
                 next

             self.Runmode.conf["usecustomrules"] = True
             self.conf["customrules"] = rules

             if self.conf.has_key("configtpl"):
                 self.useTemplateConfig()
             else:
                 p_error("Verification Runmode must have a config template supplied for the engine bailing")
                 sys.exit(1)             

             if self.run_ids(pcap, "no") == 0:
                 if os.path.exists(self.newfastlog):
                     self.parse_fast(alertdict, self.newfastlog, self.mode)

                 else:
                     resultsdict[testid] = "FAIL"
                     p_info("FAIL:Failed to find alert log file %s\n" % (str(whoami()), str(self.newfastlog)))
                     failcnt += 1
                     next
                 for match in alert_opt_regex.finditer(testMap[testid]['alerts']):
                     if alertdict.has_key(match.group('sid')):
                         #print alertdict[match.group('sid')]
                         #print alertdict[match.group('sid')][self.mode]
                         #print match.group("count")
                         if match.group('operator') == "=":
                             p_warn("equal operator found")
                             if int(match.group("count")) == int(alertdict[match.group('sid')][self.mode]): 
                                 resultsdict[testid] = "PASS"
                                 p_info("PASS:sid %s found %s in %s" % (match.group('sid'), alertdict[match.group('sid')][self.mode] , pcap))
                                 next
                             else:
                                 resultsdict[testid] = "FAIL"
                                 p_info("FAIL:sid %s found %s in %s" % (match.group('sid'), alertdict[match.group('sid')][self.mode] , pcap))
                                 break
                         elif match.group('operator') == "<":
                             if int(match.group("count")) < int(alertdict[match.group('sid')][self.mode]):
                                 resultsdict[testid] = "PASS"
                                 p_info("PASS:sid %s found %s in %s" % (match.group('sid'), alertdict[match.group('sid')][self.mode] , pcap))
                                 next
                             else:
                                 resultsdict[testid] = "FAIL"
                                 p_info("FAIL:sid %s found %s in %s" % (match.group('sid'), alertdict[match.group('sid')][self.mode] , pcap))
                                 break
                         elif match.group('operator') == ">":     
                             if int(match.group("count")) > int(alertdict[match.group('sid')][self.mode]):
                                 resultsdict[testid] = "PASS"
                                 p_info("PASS:sid %s found %s in %s" % (match.group('sid'), alertdict[match.group('sid')][self.mode] , pcap))
                                 next
                             else:
                                 resultsdict[testid] = "FAIL"
                                 p_info("FAIL:sid %s found %s in %s" % (match.group('sid'), alertdict[match.group('sid')][self.mode] , pcap))
                                 break 
                         elif match.group('operator') == "<=":
                             if int(match.group("count")) <= int(alertdict[match.group('sid')][self.mode]):
                                 resultsdict[testid] = "PASS"
                                 p_info("PASS:sid %s found %s in %s" % (match.group('sid'), alertdict[match.group('sid')][self.mode] , pcap))
                                 break 
                             else:
                                 resultsdict[testid] = "FAIL"
                                 p_info("FAIL:sid %s found %s in %s" % (match.group('sid'), alertdict[match.group('sid')][self.mode] , pcap))
                                 break 
                         elif match.group('operator') == ">=":
                             if int(match.group("count")) >= int(alertdict[match.group('sid')][self.mode]):
                                 resultsdict[testid] = "PASS"
                                 p_info("PASS:sid %s found %s in %s" % (match.group('sid'), alertdict[match.group('sid')][self.mode] , pcap))
                                 next
                             else:
                                 resultsdict[testid] = "FAIL"
                                 p_info("FAIL:sid %s found %s in %s" % (match.group('sid'), alertdict[match.group('sid')][self.mode] , pcap))
                                 break 
                         elif match.group('operator') == "!=":
                             if int(match.group("count")) != int(alertdict[match.group('sid')][self.mode]):
                                 resultsdict[testid] = "PASS"
                                 p_info("PASS:sid %s found %s in %s" % (match.group('sid'), alertdict[match.group('sid')][self.mode] , pcap))
                                 next
                             else:
                                 resultsdict[testid] = "FAIL"
                                 p_info("FAIL:sid %s found %s in %s" % (match.group('sid'), alertdict[match.group('sid')][self.mode] , pcap))
                                 break 
                         else:
                             resulstsdict[testid] = "FAIL"
                             p_info("FAIL:sid %s not found in %s" % (sid, pcap))
                             break
                     elif int(match.group("count")) == 0:
                         resultsdict[testid] = "PASS"
                         p_info("PASS:sid %s not found in pcap %s but expected" % (match.group('sid'), pcap))
                         next
                     else:
                         resultsdict[testid] = "FAIL"
                         p_info("FAIL:IDS Failure")
                         break;
             else:
                   resultsdict[testid] = "FAIL"
                   p_info("FAIL:IDS Failure")
                   break 
             if resultsdict[testid] == "PASS":
                 successcnt += 1
             else:
                failcnt += 1

        reportfile = "%s/verify-report-%s.txt" % (self.Runmode.conf["globallogdir"], str(self.currentts))
        report = open(reportfile, 'w')
        p_info("verify results")
        report.write("verify results\n")
        for key,value in resultsdict.iteritems():
            p_info("%s:%s" % (key,value))
            report.write("%s:%s\n" % (key,value))
        p_info("successcnt:%i" % successcnt)
        report.write("successcnt:%i\n" % successcnt)
        p_info("failcnt:%i" % failcnt)
        report.write("failcnt:%i\n" % failcnt)
        for key,value in resultsdict.iteritems():
            print "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
            print "%s:%s" % (key,value)
            print "description: %s" % (testMap[key]["description"])
            print "notes: %s" % (testMap[key]["notes"])
            print "behavior: %s" % (testMap[key]["behavior"])
            print "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
        report.close()                    
                    
