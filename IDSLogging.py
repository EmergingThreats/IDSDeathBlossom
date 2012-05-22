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

import logging
import sys

#TODO: Fix this mess of global scope... ;)
abd=None
logger = abd
p_debug=abd
p_info=abd
p_warn=abd
p_error=abd
p_critical=abd

LOG_LEVEL=logging.DEBUG
LOG_FILENAME=''

# create logger
if logger == None:
    logger = logging.getLogger(sys.argv[0])
    p_debug=logger.debug
    p_critical=logger.critical
    p_error=logger.error
    p_info=logger.info
    p_warn=logger.warn

def LogInit():
    global logger
    logger.setLevel(LOG_LEVEL)
    
    # create console handler and set level to debug
    ch = logging.StreamHandler()
    ch.setLevel(LOG_LEVEL)
    
    # Add the log message handler to the logger
    handler = logging.FileHandler(LOG_FILENAME, "a")
    
    #funcName create formatter
    formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(funcName)s - %(name)s +%(lineno)s - %(message)s")
    
    # add formatter to ch
    ch.setFormatter(formatter)
    handler.setFormatter(formatter)

    # add ch to logger
    logger.addHandler(handler)
    logger.addHandler(ch)
    
    logger.debug("Logger initialized!")

def SetLogLevel(level):
    global LOG_LEVEL
    if level == "debug":
        LOG_LEVEL = logging.DEBUG
    elif level == "info":
        LOG_LEVEL = logging.INFO
    elif level == "warn":
        LOG_LEVEL = logging.WARN
    elif level == "error":
        LOG_LEVEL = logging.ERROR
    elif level == "critical":
        LOG_LEVEL = logging.CRITICAL
    else:
        LOG_LEVEL = logging.INFO

def SetLogFilename(filename):
    global LOG_FILENAME
    LOG_FILENAME=filename

