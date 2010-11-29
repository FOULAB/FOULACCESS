#!/usr/bin/env python

import sys

import httplib
import urllib2
import base64

import threading

from xml.dom.minidom import *
from hashlib import md5


class Switch( object ):
    
    def __init__( self, *nodes, **nodeids ):
        try:
            self._nodes  = [ node.info for node in nodes]
            self._nodeids = [ node.id for ID in nodeids ]
        except e:
            print 'The following error occured: ' + e
            sys.exit(1)

        self._CMD = ''
        self._payload = '<?XML version="1.0"?><?RMCXML version="1.0"?><RMCSEQ><REQ CMD="xml2cli2"><CMDINPUT>' + self._CMD  + '</CMDINPUT></REQ></RMCSEQ>'

    def __del__( self ):
        pass

    def query( self ):
        pass

    def STATE( self, ):
        cmd = 'd3debug propget ENABLE_TELNET'
        self._CMD = cmd

    def ON( self ):
        cmd = 'd3debug propset ENABLE_TELNET=TRUE'
        self._CMD = cmd

        for 

    def OFF( self ):
        cmd = 'd3debug propset ENABLE_TELNET=FALSE'
        self._CMD = cmd


    
