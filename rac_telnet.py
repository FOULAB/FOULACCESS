#!/usr/bin/env python 

import os
import sys

import re
import telnetlib

from socket import *

from xml.dom.minidom import *

class Racamd( self ):
    pass

class Command( self ):
    pass

class Node( object ):
    
    def __init__( self, *args, **kwargs ):
        self._credentials = {'username' : None,
                             'password' : None
                             }
        self._commandQueue = []
        
    def __del__( self ):
        pass

    def authenticate( self ):
        pass    

    def connect( self ):
        pass

    def disconnect( self ):
        pass

    

