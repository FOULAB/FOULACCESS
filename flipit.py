#!/usr/bin/env python
#
# Blatantly ripped off in large part from 
#
# http://svn.osgdc.org/browse/~raw,r=4748/kusu/sandbox/kusu-2.1-upgradability/src/kits/base/packages/kusu-power/src/powerplugins/dellrac.py
#

import time
import httplib
import base64
import re
import sys
from getpass import getpass
import xml.sax
from hashlib import md5

class RCHandler( xml.sax.ContentHandler ):
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
    
    def processingInstriction(self, target, data):
        pass

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
            ret_dict = {'code' : self.responsecode, \
                        'msg' : self.rc_decode[self.responsecode]}
        except:
            ret_dict = {'code' : self.responsecode, \
                        'msg' : 'Unknown error from RAC server'}

        return ret_dict



class RACHandler( xml.sax.ContentHandler ):

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

    def get_challenge(self):
        return self.challenge


class RAC( object ):

    def __init__( self, host, user, pwd ):
        self._auth = { 'USER' : user,
                       'PASS' : pwd } 
        self._host = host
        
        

        self._challenge = None
        self._sessionID = self.login()

    def __del__( self ):
        pass

    def crc16( self, hash ):
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


    def hashGen( self, password, challenge ):
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
            challenge_bytes[i] = ord( challenge_bytes[i] ) 
    
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

        crc = self.crc16( hash )
        hash = hash + chr(crc & 0xff) + chr(crc >> 8 & 0xff)
        hash = base64.encodestring(hash)
        return re.sub("\n", "", hash)


    def login( self ):
        
        XML_handler = RACHandler()
        RC_handler = RCHandler()

        conn = httplib.HTTPSConnection( self._host )

        conn.putrequest( 'GET', '/cgi/challenge' )
        conn.putheader( 'User-Agent', 'Scali/1.0' )
        conn.endheaders()
        http_response = conn.getresponse()

        if http_response.status != 200:
            raise Exception, "%d %s" % (http_response.status, str(http_response.reason))

        cookie = http_response.getheader('Set-Cookie')
        xml_content = http_response.read()
        conn.close()

        xml.sax.parseString(xml_content, RC_handler)
        if RC_handler.get_rc()['code'] != str('0x0'):
            raise Exception, "Failed with error code {0}, {1}".format( RC_handler.get_rc()['code'], RC_handler.get_rc()['msg'] )

        xml.sax.parseString(xml_content, XML_handler)
        challenge = XML_handler.get_challenge()

        self._challenge = challenge
        
        if re.match( 'sid=', cookie ):
            session_id = cookie.split()[0]
            session_id = re.sub('sid=', '', session_id)
            session_id = re.sub(';', '', session_id)
        else:
            raise Exception, "Response from RAC server contained no Session ID"

        # Phase 2. (of 3) Making password hash
        hash = self.hashGen( self._auth['PASS'], challenge )
        if not hash:
            raise Exception, "Hash string empty"

        # Phase 3. (of 3) Connecting with hashed password
        conn = httplib.HTTPSConnection(self._host)

        conn.putrequest( 'GET', '/cgi/login?user={0}&hash={1}'.format( self._auth['USER'], hash ) )
        conn.putheader( 'Cookie', 'sid=' + session_id )
        conn.putheader( 'User-Agent', 'Scali/1.0' )
        conn.endheaders()
        http_response = conn.getresponse()
        if http_response.status != 200:
            raise Exception, "{0} {1}".format( http_response.status, str(http_response.reason) )

        cookie = http_response.getheader( 'Set-Cookie' )
        xml_content = http_response.read()
        conn.close()

        xml.sax.parseString(xml_content, RC_handler)
        if RC_handler.get_rc()['code'] != str('0x0'):
            raise Exception, "Failed with error code {0}, {1}".format( RC_handler.get_rc()['code'], RC_handler.get_rc()['msg'] )

        return session_id


    def command(self, xml_command):

        conn = httplib.HTTPSConnection(self.host)

        headers = { "Content-type": "application/x-www-form-urlencoded",
                    "Cookie": "sid=" + self._sessionID,
                    "User-Agent": "Scali/1.0" }            
        conn.request( 'POST', "/cgi/bin", xml_command, headers )
        http_response = conn.getresponse()
        if http_response.status != 200:
            raise Exception, "{0} {1}".format( http_response.status, str( http_response.reason ) )
        
        cookie = http_response.getheader( 'Set-Cookie' )
        xml_content = http_response.read()
        conn.close()
       
        return xml_content



class Telnet( object ):
    
    def __init__( self, rac ):
        self._RAC = rac

    def __del__( self ):
        pass

    def payload( self, cmd ):
        return '<?XML version="1.0"?><?RMCXML version="1.0"?><RMCSEQ><REQ CMD="xml2cli2"><CMDINPUT>{0}</CMDINPUT></REQ></RMCSEQ>'.format( cmd )

    def ON( self ):
        cmd = 'd3debug propset ENABLE_TELNET=TRUE'
        self._RAC.command( self.payload( cmd ) )

    def OFF( self ):
        cmd = 'd3debug propset ENABLE_TELNET=FALSE'
        self._RAC.command( self.payload( cmd ) )



if __name__ == "__main__":
    
    state = raw_input( 'Type "On" or "Off": ' )
    cred = []
    cred.append( raw_input('Node IP: ') )
    cred.append( raw_input('Username: ') )
    cred.append( getpass('Password: ') )
    
    NODE = RAC( cred[0], cred[1], cred[2] )
    
    TELNET = Telnet( NODE )
    
    if state == 'On':
        TELNET.ON()

    if state == 'Off':
        TELNET.OFF()
    

    
