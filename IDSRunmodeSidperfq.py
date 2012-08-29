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
from IDSLogging import *
from IDSdb import *

import time


class RunmodeSidperfq:
    def sidperfreport(self):
        lines=[]
        alerts_in={}
        total_alerts = 0
        total_checks = 0
        total_matches = 0
        total_microsecs = 0

        perfsum = "%s/SidPerfReport-%s-%s.txt" % (self.Runmode.conf["globallogdir"],str(self.Runmode.conf["sperfsid"]), time.strftime("%Y-%m-%d-T-%H-%M-%S", time.localtime()))
        report = open(perfsum, 'w')
        report.write("historical data for sid %s\n\n" % (str(self.Runmode.conf["sperfsid"])))
        cur = self.db.execute("select runid, file, alertfile, engine, rank, sid, gid, rev, checks, matches, alerts, microsecs, avgtcheck, avgtmatch, avgtnomatch from rulestats where sid=\'%s\' order by id desc" % (self.Runmode.conf["sperfsid"]))

        if not cur:
            p_warn('No data available')
        else:
            for row in cur:
                (runid,file,alertfile,engine,rank,sid,gid,rev,checks,matches,alerts,microsecs,avgtcheck,avgmatch,avgtnomatch) = row
                lines.append("%s %s %s %s %s %s %s %s %s %s %s %s %s %s\n" % (runid,file,alertfile,engine,rank,gid,rev,checks,matches,alerts,microsecs,avgtcheck,avgmatch,avgtnomatch))
                total_alerts += int(alerts)
                total_checks += int(checks)
                total_matches += int(matches)
                total_microsecs += float(microsecs)
    
                if alerts > 0:
                    alerts_in[alertfile] = "run-id:%s pcap:%s number of alerts:%s\n" % (str(runid),str(file),str(alerts))

        report.write("total alerts %i\n" % total_alerts)
        report.write("total checks %i\n" % total_checks)
        report.write("total_matches %i\n" % total_matches)
        report.write("total_microsecs %i\n" % total_microsecs)
        report.write("\n\n")

        #for (key,value) alerts_in.iteritems():
        #    report.write("alertfile:%s\n %s" % (key,value)
        report.write("\n\n")

        report.write("runid, file, alertfile, engine, rank, sid, gid, rev, checks, matches, alerts,microsecs, avgtcheck, avgtmatch, avgtnomatch\n")
        for line in lines:
            report.write(line)

        report.close()

        if "sidperfq" in self.Runmode.conf["emailonarr"]:
            filearr=[perfsum]
            #send_email(self.options.emailsrc, self.emaildstarr, str(self.options.emailsubject) + "Rule Perf Summary Report for sid " + self.Runmode.conf["sperfsid"], None, self.options.emailsrv, filearr)
            self.Mail.sendEmail("Rule Perf Summary Report for sid " + self.Runmode.conf["sperfsid"], None, filearr)

    #print a top N worst performing rules report for all data in db
    def TopNWorstAll(self):
        perfsum = "%s/TopNWorstAll-summary-%s.txt" % (self.Runmode.conf["globallogdir"], str(self.currentts))
        report = open(perfsum, 'w')

        cur = self.db.execute("select sid,engine,microsecs,file from rulestats order by microsecs desc limit %s" % self.Runmode.conf["topN"])

        report.write("top %s worst performing rules by total microseconds\n" % self.Runmode.conf["topN"])
        report.write("sid,microsecs,file\n")
        if cur:
            for row in cur:
                report.write("%s\n" % str(row))
        else:
            p_warn("No data available")
        report.write("\n")

        report.write("top %s worst performing rules by avg ticks per non-match\n" % self.Runmode.conf["topN"])
        cur = self.db.execute("select sid,engine,avgtnomatch,file from rulestats order by avgtnomatch desc limit %s" % self.Runmode.conf["topN"])
        report.write("sid,avgtnomatch,file,cmd\n")
        if cur:
            for row in cur:
                report.write("%s\n" % str(row))
            report.write("\n")
        else:
            p_warn("No data available")

        report.write("top %s worst performing rules by avg ticks per check\n" % self.Runmode.conf["topN"])
        cur = self.db.execute("select sid,engine,avgtcheck,file from rulestats order by avgtcheck desc limit %s" % self.Runmode.conf["topN"])
        report.write("sid,avgtcheck,file\n")
        if cur:
            for row in cur:
                report.write("%s\n" % str(row))
            report.write("\n")
        else:
            p_warn("No data available")
        
        report.write("top %s worst performing rules by avg ticks per match\n" % self.Runmode.conf["topN"])
        cur = self.db.execute("select sid,engine,avgtmatch,file from rulestats order by avgtmatch desc limit %s" % self.Runmode.conf["topN"])
        report.write("sid,avgtcheck,file\n")
        if cur:
            for row in cur:
                report.write("%s\n" % str(row))
            report.write("\n")
        else:
            p_warn("No data available")
 
        report.write("top %s worst performing rules by number of checks\n" % self.Runmode.conf["topN"])
        cur = self.db.execute("select sid,engine,checks,file from rulestats order by checks desc limit %s" % self.Runmode.conf["topN"])
        report.write("sid,avgtcheck,file\n")
        if cur:
            for row in cur:
                report.write("%s\n" % str(row))
            report.write("\n")
        else:
            p_warn("No data available")

        report.close()

        if "TopNWorstAll" in self.Runmode.conf["emailonarr"]:
            filearr=[perfsum]
            #send_email(self.options.emailsrc, self.emaildstarr, str(self.options.emailsubject) + "Rule Perf Summary Report TopNWorstAll", None, self.options.emailsrv, filearr)
            self.Mail.sendEmail("Rule Perf Summary Report TopNWorstAll", None, filearr)

    def TopNWorstCurrent(self):
        perfsum = "%s/TopNWorstCurrent-%s.txt" % (self.Runmode.conf["globallogdir"], str(self.currentts))
        report = open(perfsum, 'w')
        report.write("top %s worst performing rules by total microseconds\n" % self.Runmode.conf["topN"])
        cur = self.db.execute("select sid,engine,microsecs,file from rulestats where runid=\'%s\' order by microsecs desc limit %s" % (self.runid,self.Runmode.conf["topN"]))
        report.write("sid,microsecs,file\n")
        for row in cur:
            report.write("%s\n" % str(row))
        report.write("\n")

        report.write("top %s worst performing rules by avg ticks per non-match\n" % self.Runmode.conf["topN"])
        cur = self.db.execute("select sid,engine,avgtnomatch,file from rulestats where runid=\'%s\' order by avgtnomatch desc limit %s" % (self.runid,self.Runmode.conf["topN"]))
        report.write("sid,avgtnomatch,file,cmd\n")
        for row in cur:
            report.write("%s\n" % str(row))
        report.write("\n")

        report.write("top %s worst performing rules by avg ticks per check\n" % self.Runmode.conf["topN"])
        cur = self.db.execute("select sid,engine,avgtcheck,file from rulestats where runid=\'%s\' order by avgtcheck desc limit %s" % (self.runid,self.Runmode.conf["topN"]))
        report.write("sid,avgtcheck,file\n")
        for row in cur:
            report.write("%s\n" % str(row))
        report.write("\n")

        report.write("top %s worst performing rules by avg ticks per match\n" % self.Runmode.conf["topN"])
        cur = self.db.execute("select sid,engine,avgtmatch,file from rulestats where runid=\'%s\' order by avgtmatch desc limit %s" % (self.runid,self.Runmode.conf["topN"]))
        report.write("sid,avgtcheck,file\n")
        for row in cur:
            report.write("%s\n" % str(row))
        report.write("\n")

        report.write("top %s worst performing rules by checks (no. of checks after fast_pattern)\n" % self.Runmode.conf["topN"])
        cur = self.db.execute("select sid,engine,checks,file from rulestats where runid=\'%s\' order by checks desc limit %s" % (self.runid,self.Runmode.conf["topN"]))
        report.write("sid,avgtcheck,file\n")
        for row in cur:
            report.write("%s\n" % str(row))
        report.write("\n")

        report.close()
        if "TopNWorstCurrent" in self.Runmode.conf["emailonarr"]:
            filearr=[perfsum]
            #send_email(self.options.emailsrc, self.emaildstarr, str(self.options.emailsubject) + "Rule Perf Summary Report TopNWorstCurrent", None, self.options.emailsrv, filearr)
            self.Mail.sendEmail("Rule Perf Summary Report TopNWorstCurrent", None, filearr)

    def LoadReportCurrent(self):
        total_ids_runtime = 0
        total_ids_alerts = 0
        total_files_processed = 0 
        perfsum = "%s/LoadReportCurrent-%s.txt" % (self.Runmode.conf["globallogdir"], str(self.currentts))
        report = open(perfsum, 'w')
        cur = self.db.execute("select runid,cmd,file,engine,runtime,exitcode,alertfile,alertcnt,ualerts from filestats where runid=\'%s\'" % (self.runid))
        #report.write("runid,cmd,file,engine,runtime,alertfile,alertcnt,exitcode\n")
        for row in cur:
            #rowarr = list(row)
            #report.write("%s\n" % str(row))
            tmpalertdict={}
            report.write("runid:%s\n" % str(row[0]))
            report.write("cmd:%s\n" % str(row[1]))
            report.write("file:%s\n" % str(row[2]))
            report.write("engine:%s\n" % str(row[3]))
            report.write("runtime:%s\n" % str(row[4]))
            report.write("exitcode:%s\n" % str(row[5]))
            report.write("+++++++++++++++++++++++++++++\n")
            report.write("alertfile:%s\n" % str(row[6]))
            report.write("total alerts:%s\n" % str(row[7]))
            report.write("alerts by sid:\n")

            #there has to be a cleaner way to do this although dict(row[8]) gives an error
            tmpstring = row[8].replace('{','').replace('}','').replace('\'','')
            #print tmpstring
            sitems = [s for s in tmpstring.split(',') if s]
            tmpalertdict = {}
            for item in sitems:
                key,value = item.split(':')
                tmpalertdict[key] = value

            for key,value in tmpalertdict.iteritems():
                report.write("%i:%i\n" % (int(key),int(value)))
            report.write("=============================\n\n")
            
            #incriment totals stats
            total_ids_runtime += float(row[4])
            total_ids_alerts += float(row[7])
            total_files_processed += 1

        report.write("\n")
        report.write("Unique Run ID:%s\n" % self.runid)
        report.write("total ids runtime:%i\n" % total_ids_runtime)
        report.write("total ids alerts:%i\n" % total_ids_alerts)
        report.write("total files processed:%i\n" % total_files_processed)
        report.close()

        if "LoadReportCurrent" in self.Runmode.conf["emailonarr"]:
            filearr=[perfsum]
            #send_email(self.options.emailsrc, self.emaildstarr, str(self.options.emailsubject) + "IDS Perf Summary Report", None, self.options.emailsrv, filearr)
            self.Mail.sendEmail("IDS Perf Summary Report", None, filearr)

    def queryDB(self, query):
        data = ''
        try:
            data = '\nResults for %s:\n' % query
            res = cur = self.db.execute(query)
            data = "%s----------------------------------------... . . .\n" % data
            data = "%s| " % data
            for t in res.description:
                    data = "%s%2s | " % (data,str(t[0]))
            data = "%s\n" % data
            data = "%s----------------------------------------... . . .\n" % data
            for row in cur:
                data = "%s| " % data
                for i in row:
                    data = "%s%2s | " % (data,str(i))
                data = "%s\n" % data
            data = "%s----------------------------------------... . . .\n" % data
        except:
            p_error("Error executing query")
            sys.exit(-321)
        print data
        if "sqlquery" in self.Runmode.conf["emailonarr"]:
            try:
                res = file(self.Runmode.conf["globallogdir"] + "/customresults.txt","w")
                res.write(data)
                res.close()
                filearr=[self.Runmode.conf["globallogdir"] + "/customresults.txt"]
                #send_email(self.options.emailsrc, self.emaildstarr, str(self.options.emailsubject) + "Rule Perf Summary Report for sid " + self.Runmode.conf["sperfsid"], None, self.options.emailsrv, filearr)
            except:
                p_error("Couldn't write the result into %s" % str(self.Runmode.conf["globallogdir"] + "/customresults.txt"))
                sys.exit(-234)
                
            self.Mail.sendEmail("Custom sql query", query + "Look at the attached results...", filearr)
            p_info("Email sent...")
