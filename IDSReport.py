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

import sys
import os
import re

from IDSLogging import *


class IDSReport:
    def __init__(self, dbhandle, title="", conf={}):
        self.title = title
        self.headers = []
        self.body = []
        self.footers = []
        self.spacechr = {}
        self.spacechr["raw"] = ' '
        self.spacechr["html"] = '&nbsp;'
        #broken
        #self.host = conf["host"] 
        self.host = "localhost"
        self.db = dbhandle

    def setData(self, data):
        self.title=data['title']
        self.headers=data['headers']
        self.body=data['body']
        self.footers=data['footers']

    def spacer(self, reportFormat, i):
        s = ''
        for i in range(0,i):
            s = "%s%s" % (s, self.spacechr[reportFormat])
        return s

    def FormatTitle(self, reportFormat, title, indent=0):
        if reportFormat == "raw":
            return self.spacer(reportFormat, indent)+ title + "\n"
        if reportFormat == "html":
            return "<p>" + self.spacer(reportFormat, indent)+ title + "</p>\n"
        return title

    def FormatLine(self, reportFormat, line, indent=0):
        if reportFormat == "raw":
            return self.spacer(reportFormat, indent)+ line + "\n"
        if reportFormat == "html":
            return "<p>" + self.spacer(reportFormat, indent)+ line + "</p>"
        return line

    def FormatListRaw(self, reportFormat, rlist, indent=1):
        data = ''
        for item in rlist:
            if type(item) == str:
                data = "%s%s" % (data, self.FormatLine(reportFormat, "- " + item, indent + 1))
            elif type(item) == list:
                data = "%s%s" % (data, self.FormatList(reportFormat, item, indent + 1))
            elif type(item) == dict:
                for k in item.keys():
                    if type(item[k]) == list:
                        data = "%s%s%s" % (data, self.FormatLine(reportFormat, "- " + k + ":", indent + 1), self.FormatList(reportFormat, item[k], indent + 1))
                    elif type(item[k]) == str:
                        data = "%s%s%s" % (data, self.FormatLine(reportFormat, "- " + k + ":", indent + 1), self.FormatLine(reportFormat, item[k], indent + 1))
            else:
                data = "%s%s" % (data, self.FormatLine(reportFormat, str(item)))
        return data

    def FormatListHtml(self, reportFormat, rlist, indent=1):
        data = ''
        data = "%s\n<table border=0>\n" % data
        for item in rlist:
            data = "%s<tr>" % data
            if type(item) == str:
                data = "%s<td colspan=2>" % data
                data = "%s%s" % (data, self.FormatLine(reportFormat, "- " + item, indent + 1))
                data = "%s</td>\n" % data
            elif type(item) == list:
                data = "%s<td colspan=2>" % data
                data = "%s%s" % (data, self.FormatList(reportFormat, item, indent + 1))
                data = "%s</td>\n" % data
            elif type(item) == dict:
                data = "%s<td colspan=2><table border=0>" % data
                for k in item.keys():
                    if type(item[k]) == list:
                        data = "%s<tr><td>%s</td><td>%s</td></tr>\n" % (data, self.FormatLine(reportFormat, "- " + k + ":", indent + 1), self.FormatList(reportFormat, item[k], indent + 1))
                    elif type(item[k]) == str:
                        m = re.search("^link_(?P<name>.*)", k)
                        if m:
                            data = "%s<tr><td>%s</td><td><a href=\"%s\">%s</a></td></tr>\n" % (data, self.FormatLine(reportFormat, "- " + k + ":", indent + 1), item[k], m.group("name"))
                        else:
                            data = "%s<tr><td>%s</td><td>%s</td></tr>\n" % (data, self.FormatLine(reportFormat, "- " + k + ":", indent + 1), self.FormatLine(reportFormat, item[k], indent + 1))
                data = "%s</table></td>\n" % data
            else:
                data = "%s<td colspan=2>" % data
                data = "%s%s" % (data, self.FormatLine(reportFormat, str(item)))
                data = "%s</td>\n" % data
            data = "%s</tr>\n" % data
        data = "%s\n</table>\n" % data
        return data

    def FormatList(self, reportFormat, rlist, indent=1):
        if reportFormat == "html":
            return self.FormatListHtml(reportFormat, rlist, indent) 
        if reportFormat == "raw":
            return self.FormatListRaw(reportFormat, rlist, indent) 

        # Default or unknown is raw
        return self.FormatListRaw(reportFormat, rlist, indent)

    def buildRaw(self, reportFormat):
        data = ""
        data = "%s%s%s" % (data, self.FormatLine(reportFormat, "Title:"), self.FormatTitle(reportFormat, self.title, 1))
        data = "%s%s%s" % (data, self.FormatLine(reportFormat, "Header:"), self.FormatList(reportFormat, self.headers))
        data = "%s%s%s" % (data, self.FormatLine(reportFormat, "Body:"), self.FormatList(reportFormat, self.body))
        data = "%s%s%s" % (data, self.FormatLine(reportFormat, "Footer:"), self.FormatList(reportFormat, self.footers))
        return data

    def buildHtml(self, reportFormat):
        data = "<html><head><title>%s</title> </head>\n<body>\n" % self.title
        data = "%s<tr><td>%s</td><td>%s</td></tr>\n" % (data, self.FormatLine(reportFormat, "Title:"), self.FormatTitle(reportFormat, self.title, 1))
        data = "%s<tr><td>%s</td><td>%s</td></tr>\n" % (data, self.FormatLine(reportFormat, "Header:"), self.FormatList(reportFormat, self.headers))
        data = "%s<tr><td>%s</td><td><strong>%s</strong></td></tr>\n" % (data, self.FormatLine(reportFormat, "Body:"), self.FormatList(reportFormat, self.body))
        data = "%s<tr><td>%s</td><td>%s</td></tr>\n" % (data, self.FormatLine(reportFormat, "Footer:"), self.FormatList(reportFormat, self.footers))
        data = "%s\n</table></body></html>\n" % data
        return data

    def storeReport(self, data, con, rtype = "sanitize"):
        #(id primary key, reportgroup, timestamp, status, engine, path, relpath, errors integer, warnings integer, time integer)
        #sqlcmd = """INSERT INTO filestats(id, timestamp, runid, cmd, file, engine, runtime, ualerts, alertfile, alertcnt, exitcode) VALUES(NULL,"%s","%s","%s","%s","%s","%f","%s","%s","%i","%i")""" % (self.currentts, self.runid, self.lastcmd, pcap, self.engine, self.elapsed, tmpsiddict, self.newfastlog, alertcnt, self.returncode)
        if rtype == "sanitize":
            (reportgroup, timestamp, status, engine, path, relpath, errors,
warnings, time, commented) = data
            sqlcmd = 'INSERT INTO report(id, reportgroup, timestamp, status, engine, path, relpath, errors, warnings, time, commented) VALUES(NULL,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)'
            params = (reportgroup, timestamp, status, engine, path, relpath, errors, warnings, time, commented)
            cur = self.db.execute(sqlcmd,params)

    def updateReport(self, data, con, rtype = "sanitize"):
        #(id primary key, reportgroup, timestamp, status, engine, path, relpath, errors integer, warnings integer, time integer)
        #sqlcmd = """INSERT INTO filestats(id, timestamp, runid, cmd, file, engine, runtime, ualerts, alertfile, alertcnt, exitcode) VALUES(NULL,"%s","%s","%s","%s","%s","%f","%s","%s","%i","%i")""" % (self.currentts, self.runid, self.lastcmd, pcap, self.engine, self.elapsed, tmpsiddict, self.newfastlog, alertcnt, self.returncode)
        if rtype == "sanitize":
            (reportgroup, timestamp, status, engine, path, relpath, errors,
warnings, time, commented) = data
            sqlcmd = 'UPDATE report SET status=%s, path=%s, relpath=%s, errors=%s, warnings=%s, time=%s, commented=%s WHERE reportgroup=%s and timestamp=%s and engine=%s'
            params = (status, path, relpath, errors, warnings, time, commented, reportgroup, timestamp, engine)
            cur = self.db.execute(sqlcmd,params)

    def save(self, path, reportFormat = "raw"):
        data = self.build(reportFormat)
        if os.path.exists(path):
            p_error("There's an already saved report!! Cannot overwrite! Skipping")
        else:
            try:
                f=open(path,"w")
                f.write(data)
                f.close()
            except:
                p_error("Problems writting report. Please, check permissions on %s" % path)
                return
            p_info("Report written to %s" % path)
        return 0
        

    def build(self, reportFormat = "raw"):
        data = ""

        if reportFormat == "obj":
            data = self.__str__()
        if reportFormat == "raw":
            data = self.buildRaw(reportFormat)
        if reportFormat == "html":
            data = self.buildHtml(reportFormat)
        return data

    def setTitle(self, title):
        self.title = title

    def addHeader(self, msg):
        self.headers.append(msg)
    def addBody(self, msg):
        self.body.append(msg)
    def addFooter(self, msg):
        self.footers.append(msg)

    def __str__(self):
        return str(self.__dict__)

'''
# Example:
r = IDSReport("This report is a Test")
r.addHeader("Sanitization report")
r.addHeader("date 23/01/2011 10:23:14")
r.addHeader({"engines": ["suri","snort2901","snort2903"]})
r.addBody({"Errors": ["error1","error2","error3"]})
r.addBody({"Warnings": ["warning1","warning2","warning3"]})
r.addFooter("Summary")
r.addFooter("3 errors, 0 warnings...")
r.addFooter("...end...")

data=r.build("raw")
print "\n-----------\nRaw:\n"
print data

print "\n-----------\nAs a python dict:\n"
print r

data=r.build("html")
print "\n-----------\nHtml:\n"
print data
'''

