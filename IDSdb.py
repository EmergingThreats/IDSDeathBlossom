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
import os
class IDSdb:

    def __init__(self, options={}):

        self.options = options
        self.dbtype = self.options["type"]

        if self.dbtype == "MYSQL":
            import MySQLdb
            p_info("DBType: %s" % self.dbtype)

            db_user = self.options["user"]
            db_pass = self.options["pass"]
            db_server = self.options["server"]
            db_scheme = self.options["scheme"]

            self.db = MySQLdb.connect(host=db_server,user=db_user, passwd=db_pass,db=db_scheme)

    def query(self, cmd, params):
        self.last_result = None
        p_debug("Trying to query " + cmd)
        import MySQLdb
        try:
            cur = self.db.cursor()
            cur.execute(cmd,params)
            self.last_result = cur.fetchall()
            cur.close()
            self.db.commit()
        except MySQLdb.Error, e:
            print "Error!!!"
            p_error("Error executing query %d %s" % e.args[0], e.args[1])
            return None

        return self.last_result

    def mass_execute(self, cmd, params):
        self.last_result = None
        p_debug("Trying to query " + cmd)
        import MySQLdb
        try:
            cur = self.db.cursor()
            cur.executemany(cmd,params)
            self.last_result = cur.fetchall()
            cur.close()
            self.db.commit()
        except MySQLdb.Error, e:
            print "Error!!!"
            p_error("Error executing query %d %s" % e.args[0], e.args[1])
            return None

        return self.last_result

    # An alias for query
    def execute(self, cmd, params):
        return self.query(cmd, params)

    def commit(self):
        self.db.commit()

    def close(self):
        self.db.close()

    def initMysqlTables(self):
        #Todo, check if the db tables are present or not. Try to create them if needed
        pass

# Usage example:

#db = IDSdb()
#la = db.query("drop table test;")
#db.close()

