#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# $Id: dellrac.py 4688 2010-04-05 17:00:18Z ltsai $
#
# Disabling several pylint warnings (no time to clean up at this time)
# pylint: disable-msg=C0111,C0103,C0321
# pylint: disable-msg=W0102,W0702,W0104,W0612,W0622
#
# Module --------------------------------------------------------------------
#
# $RCSfile$
#
# Copyright 2010 Platform Computing Inc.
#
# Licensed under GPL version 2; See COPYING for details.
#
# CREATED
#   Author: sp
#   Date:   2006/06/24
#
# LAST CHANGED
#   $Author: $
#   $Date: $
#
# ---------------------------------------------------------------------------

import time
import httplib
import base64
import re
import sys

try:
    import xml.sax
except:
    print  "Error. Required xml.sax module not found by Python."
    sys.exit(1)

try:
    from hashlib import md5
except ImportError:
    from md5 import md5

# ------------------------------------------------------------------------------
# Handles XML responses in the format:
# <RC>0x140000</RC>
# ------------------------------------------------------------------------------
class _RCHandler(xml.sax.ContentHandler):
    # Static codes
    rc_decode = {'x':'Unknown error!'}
    rc_decode['0x0'      ] = 'Success'
    rc_decode['0x408'    ] = 'Session Timeout'
    rc_decode['0x43'     ] = 'Unknown command'
    rc_decode['0x140000' ] = 'Too many sessions'
    rc_decode['0x140004' ] = 'Invalid password'
    rc_decode['0x140005' ] = 'Invalid username'
    rc_decode['0x160006' ] = 'Error in SID?'
    rc_decode['0x170003' ] = 'Missing content in POST ?'
    rc_decode['0x20308'  ] = 'Console not available'
    rc_decode['0x30003'  ] = 'Console not active'
    rc_decode['0x3000a'  ] = 'Console active'
    rc_decode['0xe0003'  ] = 'Unknown serveraction'

    elements = ['RC']
    bool_responscode = 'false'
    responsecode = ''
    
    # ----------------------------------------    
    # Parser API
    # ----------------------------------------    
    
    def processingInstriction(self, target, data): pass

    def startDocument(self):
        bool_responscode = 'false'
        responsecode = ''
  
    def startElement(self,  name, attrs):
        if name == self.elements[0]:
            self.bool_responscode = 'true'

    def characters(self, string):
        if self.bool_responscode == 'true':
            self.responsecode = str(string)
            self.bool_responscode == 'false'
 
    def endElement(self, name):
        if name == self.elements[0]:
            self.bool_responscode = 'false'
       
    # ----------------------------------------    
    # Public API
    # ----------------------------------------    
    def get_rc(self):
        ret_dict = ''

        try:
            ret_dict = {'code' : self.responsecode, 
                        'msg' : self.rc_decode[self.responsecode]}
        except:
            ret_dict = {'code' : self.responsecode, 
                        'msg' : 'Unknown error from RAC server'}

        return ret_dict
    
# ------------------------------------------------------------------------------
# Handles XML content
# ------------------------------------------------------------------------------
class _RACHandler(xml.sax.ContentHandler):

    elements = ['CHALLENGE', 'PROPTEXT', 'CMDOUTPUT']

    bool_challenge = 'false'
    challenge = ''
    bool_proptext = 'false'
    proptext = ''
    bool_cmdoutput = 'false'
    cmdoutput = ''

    # ----------------------------------------    
    # Parser API
    # ----------------------------------------    
    def processingInstriction(self, target, data):
        pass

    def startDocument(self):
        self.bool_challenge = 'false'
        self.challenge = ''
        self.bool_proptext = 'false'
        self.proptext = ''
        self.bool_cmdoutput = 'false'
        self.cmdoutput = ''
        
    def startElement(self, name, attrs):
        if name == self.elements[0]:
            self.bool_challenge = 'true'
        elif name == self.elements[1]:
            self.bool_proptext = 'true'
        elif name == self.elements[2]:
            self.bool_cmdoutput = 'true'
            
    def characters(self, string):
        if self.bool_challenge == 'true':
            self.bool_challenge = 'false'
            self.challenge = string
        elif self.bool_proptext == 'true' and string != '\n':
            self.proptext = string
        elif self.bool_cmdoutput == 'true' and string != '\"':
            self.cmdoutput = self.cmdoutput + string

    def endElement(self, name):
        if name == self.elements[0]:
            self.bool_challenge = 'false'
        elif name == self.elements[1]:
            self.bool_proptext = 'false'
        elif name == self.elements[2]:
            self.bool_cmdoutput = 'false'

    # ----------------------------------------    
    # Public API
    # ----------------------------------------    
    def get_challenge(self):
        return self.challenge

    def get_power_status(self):
        # D_SYS_PWR_STATUS = ON
        # D_SYS_PWR_STATUS = OFF
        return self.proptext.split("=")
    
    def get_power_status_v2(self):
        # (v2.x SYSPWR_STATUS=0x1) => OFF
        # (v2.x SYSPWR_STATUS=0x2) => ON
        codemap = {'0x1':'OFF', '0x2': 'ON'}
        tmp = self.cmdoutput.split()[0]
        tmp = tmp.split('=')
        tmp[1] = codemap[tmp[1]]
        return tmp
    
    def get_cmdoutput(self):
        return str(self.cmdoutput)


# ----------------------------------------    
# RAC instance class
# ----------------------------------------      
class _RACInstance:
    """
    A RAC instance class
    """
    def __init__(self, log, options):
        if not options:
            raise Exception, "Not enough options given to perform operation"

        options = options.split()
        if len(options) < 3:
            raise Exception, "Not enough options given to perform operation"

        self.log = log
        self.host = options[0]
        self.user = options[1]
        self.passwd = options[2]
        # Authenticate
        self.session_id = self._login()
        # Get firmware version
        self.firmware_rev = self._getFirmwareVersion()

        self._STATUS = None
    # ----------------------------------------    
    # Private functions
    # ----------------------------------------      

    # ---- Compute a 16 bit crc on a md5 hash
    def _crc16(self, hash):
        str = hash
        crc = 0L
        t = len(str) 
        s = ''
    
        for k in range(0, t):
            s = str[k:k+1]   # substring
            s = ord(s)       # numeric ASCII value of first character
            s = s << 8       # shift left 8
            crc = crc ^ s    # bitwise exclusive OR operator

            for x in range(0, 8):
                if ((crc & 0x8000) == 32768):
                    crc = long((crc<<1) ^ 0x1021)
                else:
                    crc = long(crc<<1)

        crc = crc & 0xFFFF
        return crc

    # ---- Create a md5 hash based on password and challenge
    def _mkhash(self, password, challenge):
        c_bytes = ''
        p_bytes = ''
        challenge_bytes = []
        pwd_hash = []
        xor_bytes = []
        
        c_bytes         = base64.decodestring(challenge)
        challenge_bytes = list(c_bytes)
        challenge_bytes = challenge_bytes[0:16] 

        # Convert to unsigned char:
        for i in range(0, 16):
            challenge_bytes[i] = ord(challenge_bytes[i]) 
    
        m = md5()
        m.update(password)
        p_bytes         = m.digest()
        pwd_hash        = list(p_bytes)
        pwd_hash        = pwd_hash[0:16]

        # Convert to unsigned char:
        for i in range(0, 16):
            pwd_hash[i] = ord(pwd_hash[i]) 

        # XOR
        for i in range(0, 16):
            xor_bytes.append(challenge_bytes[i] ^ pwd_hash[i])

        # List to string (16)
        hb = ''
        for i in range(0, 16):
            hb =   hb + chr(xor_bytes[i]) 

        mm = md5()
        mm.update(hb)
        hash = mm.digest()

        crc = self._crc16(hash)
        hash = hash + chr(crc & 0xff) + chr(crc >> 8 & 0xff)
        hash = base64.encodestring(hash)
        return re.sub("\n", "", hash)

    # ---- Login -----
    def _login(self):

        XML_handler = _RACHandler()
        RC_handler = _RCHandler()
        
        # Phase 1. (of 3) Get Session ID and password challenge
        self.log.debug("Opening https connection to {0} (Challenge)".format( self.host ))
        conn = httplib.HTTPSConnection( self.host )

        conn.putrequest('GET', '/cgi/challenge')
        conn.putheader('User-Agent', 'Scali/1.0')
        conn.endheaders()
        http_response = conn.getresponse()
        if http_response.status != 200:
            raise Exception, "{0} {1}".format(http_response.status, str(http_response.reason))

        cookie = http_response.getheader('Set-Cookie')
        self.log.debug( cookie )
        xml_content = http_response.read()
        conn.close()

        self.log.debug( xml_content )
            
        xml.sax.parseString(xml_content, RC_handler)
        if RC_handler.get_rc()['code'] != str('0x0'):
            raise Exception, "Failed with error code {0}, {1}".format(RC_handler.get_rc()['code'], RC_handler.get_rc()['msg'])

        xml.sax.parseString(xml_content, XML_handler)
        challenge = XML_handler.get_challenge()

        self.log.debug("{0}: Challenge '{1}'".format(self.host, challenge))
        
        if re.match('sid=', cookie):
            session_id = cookie.split()[0]
            session_id = re.sub('sid=', '', session_id)
            session_id = re.sub(';', '', session_id)
        else:
            raise Exception, "Response from RAC server contained no Session ID"

        self.log.debug("{0}: SID {1}".format(self.host, session_id))

        # Phase 2. (of 3) Making password hash
        hash = self._mkhash(self.passwd, challenge)
        if not hash:
            raise Exception, "Hash string empty"
        ## FUCK YOU DELL
        hash = self.passwd
        # Phase 3. (of 3) Connecting with hashed password
        self.log.debug("Opening https connection to {0} (Authenticate)".format(self.host))
        conn = httplib.HTTPSConnection(self.host)
        hash = 'calvin'
        conn.putrequest('GET', '/cgi/login?user={0}&hash={1}'.format(self.user, hash))
        conn.putheader('Cookie', 'sid=' + session_id)
        conn.putheader('User-Agent', 'Scali/1.0')
        conn.endheaders()
        http_response = conn.getresponse()
        if http_response.status != 200:
            raise Exception, "{0} {1}".format(http_response.status, str(http_response.reason))

        cookie = http_response.getheader('Set-Cookie')
        xml_content = http_response.read()
        self.log.debug( xml_content )
        conn.close()

        xml.sax.parseString(xml_content, RC_handler)
        if RC_handler.get_rc()['code'] != str('0x0'):
            raise Exception, "Failed with error code {0}, {1}".format(RC_handler.get_rc()['code'], RC_handler.get_rc()['msg'])

        return session_id
        
    # ---- Sending command and receiving output -----
    def _executeCommand(self, xml_command):

        RC_handler = _RCHandler()

        self.log.debug("Opening https connection to {0} (Command)".format( self.host ))
        conn = httplib.HTTPSConnection(self.host)

        headers = {"Content-type": "application/x-www-form-urlencoded",
                   "Cookie": "sid=" + self.session_id,
                   "User-Agent": "Scali/1.0"}          
        conn.request('POST', "/cgi/bin", xml_command, headers)
        http_response = conn.getresponse()
        if http_response.status != 200:
            raise Exception, "{0} {1}".format(http_response.status, str(http_response.reason))
        
        cookie = http_response.getheader('Set-Cookie')
        xml_content = http_response.read()
        conn.close()

        xml.sax.parseString(xml_content, RC_handler)
        if RC_handler.get_rc()['code'] != str('0x0'):
            raise Exception, "Failed with error code {0}, {1}".format(RC_handler.get_rc()['code'], RC_handler.get_rc()['msg'])
       
        return xml_content

    # ---- Determine RAC firmware version ----
    def _getFirmwareVersion(self):

        XML_handler = _RACHandler()

        xml_command = "<?XML version=\"1.0\"?>" +\
                      "<?RMCXML version=\"1.0\"?>" +\
                      "<RMCSEQ>" +\
                      "<REQ CMD=\"xml2cli\">" +\
                      "<CMDINPUT>getsysinfo -A</CMDINPUT>" +\
                      "</REQ>" +\
                      "</RMCSEQ>"
        xml_output = self._executeCommand(xml_command)
        xml.sax.parseString(xml_output, XML_handler)

        tmplist = XML_handler.get_cmdoutput()
        tmplist = re.sub('\&quote', "\"",  tmplist)
        tmplist = tmplist.split("\n")
        tmplist = list(tmplist)

        racinfo = tmplist[0].split()[2:]
        fwrev =  ""
        for item in racinfo:
            try:
                f = float(item)
                if item.find(".") == -1:
                    raise Exception
                fwrev = item
                break
            except:
                pass

        self.log.debug("RAC Firmware version: {0}".format(fwrev))
        return fwrev
        
    # ----------------------------------------    
    # Public functions
    # ----------------------------------------      

    def powerStatus(self):

        XML_handler = _RACHandler()
        
        if float(self.firmware_rev) <= 1.07:
            xml_command = "<?XML version=\"1.0\"?>" +\
                          "<?RMCXML version=\"1.0\"?>" +\
                          "<RMCSEQ>" +\
                          "<REQ CMD=\"fwconfig\">" +\
                          "<ACTION>get</ACTION>" +\
                          "<USERNAMES></USERNAMES>" +\
                          "<PROPNAMES>D_SYS_PWR_STATUS</PROPNAMES>" +\
                          "</REQ>" +\
                          "</RMCSEQ>"
        else:
            xml_command = "<?XML version=\"1.0\"?>" +\
                          "<?RMCXML version=\"1.0\"?>" +\
                          "<RMCSEQ>" +\
                          "<REQ CMD=\"xml2cli\">" +\
                          "<CMDINPUT>serverstatus</CMDINPUT>" +\
                          "</REQ>" +\
                          "</RMCSEQ>"

        xml_output = self._executeCommand(xml_command)
        xml.sax.parseString(xml_output, XML_handler)
        if float(self.firmware_rev) > 1.07:
            pwstat = str(XML_handler.get_power_status_v2()[1]);
        else:
            pwstat = str(XML_handler.get_power_status()[1]);
######## IMPORTANT TO APPLY TO MY MODULE
        if pwstat == "OFF":
            #return kusu.power.STATUSOFF
            print "SERVER IS DOWN"
            self._STATUS = False
        elif pwstat == "ON":
            #return kusu.power.STATUSON
            print "SERVER IS UP"
            self._STATUS = True
        #return kusu.power.STATUSNA
        print "STATUS NOT AVAILABLE"
        self._STATUS = None

    def powerOff(self):

        xml_command = "<?XML version=\"1.0\"?>" +\
                      "<?RMCXML version=\"1.0\"?>" +\
                      "<RMCSEQ>" +\
                      "<REQ CMD=\"serveraction\">" +\
                      "<ACT>powerdown</ACT>" +\
                      "</REQ>" +\
                      "</RMCSEQ>"
        self._executeCommand(xml_command)
        #return kusu.power.SUCCESS
        print "SERVER POWERDOWN SUCCESFUL"

    def powerOn(self):
        
        xml_command = "<?XML version=\"1.0\"?>" +\
                      "<?RMCXML version=\"1.0\"?>" +\
                      "<RMCSEQ>" +\
                      "<REQ CMD=\"serveraction\">" +\
                      "<ACT>powerup</ACT>" +\
                      "</REQ>" +\
                      "</RMCSEQ>"
        self._executeCommand(xml_command)
        #return kusu.power.SUCCESS
        print "SERVER BOOTUP SUCCESFUL"

class dellrac( object ):
    """
    Manage Dell RAC power devices
    """
    
    # ----------------------------------------    
    # Public functions
    # ----------------------------------------      
    
    def powerStatus(self, node, options):
        self.log.debug("{0}: Checking powerstatus for {1}".format(self.__name__, node))
        rac = _RACInstance(self.log, options)
        return rac.powerStatus()

    def powerOff(self, node, options):
        rac = _RACInstance(self.log, options)
        # NB! check powerstatus if off do not turn off
        status = rac.powerStatus()
        if status == False:
            self.log.debug("{0}: Node {1} is already turned off".format(self.__name__, node))
            return kusu.power.SUCCESS
        self.log.debug("{0}: Turning off {1}".format(self.__name__, node))
        return rac.powerOff()

    def powerOn(self, node, options):
        rac = _RACInstance(self.log, options)
        # NB! check powerstatus if on do not turn on
        status = rac.powerStatus()
        if status == True:
            self.log.debug("%s: Node %s is already turned on" % (self.__name__, node))
            return kusu.power.SUCCESS
        self.log.debug("%s: Turning on %s" % (self.__name__, node))
        return rac.powerOn()

    def powerCycle(self, node, options):
        rac = _RACInstance(self.log, options)
        status = rac.powerStatus()
        if status == kusu.power.STATUSON:
            self.log.debug("{0}: powerstatus is ON - cycling node : {1}".format(self.__name__, node))
            rac.powerOff()
            # RAC needs time between cmds
            time.sleep(10)
            rac.powerOn()
        elif status == kusu.power.STATUSOFF:
            self.log.debug("{0}: powerstatus is OFF - turning on node: {1}".format(self.__name__, node))
            rac.powerOn()
        else:
            raise Exception, "Unable to determine power state for node {}".format(node)

        print "SUCCESS!"


