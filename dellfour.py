import time
from fou_dellrac import _RACInstance

class DEBUG( object ):
    
    def __init__( self ):
        self._TIME = "_".join( time.ctime().split() )
        self._FILE = file( self._TIME + '.dmp', 'w' )

    def __del__( self ):
        self._FILE.close()

    def debug( self, *dumping ):
        self._FILE.write( ' '.join( dumping ) + '\n' )


class Telnet( object ):
    
    def __init__( self, rac ):
        self._RAC = rac

    def __del__( self ):
        pass

    def payload( self, cmd ):
        return '<?XML version="1.0"?><?RMCXML version="1.0"?><RMCSEQ><REQ CMD="xml2cli2"><CMDINPUT>{0}</CMDINPUT></REQ></RMCSEQ>'.format( cmd )

    def ON( self ):
        cmd = 'd3debug propset ENABLE_TELNET=TRUE'
        self._RAC._executeCommand( self.payload( cmd ) )

    def OFF( self ):
        cmd = 'd3debug propset ENABLE_TELNET=FALSE'
        self._RAC._executeCommand( self.payload( cmd ) )

class Server( object ):
    
    def __init__( self, rac ):
        self._RAC = rac

    def __del__( self ):
        pass

    def ON( self ):
        status = self._RAC.powerStatus()
        if status == True:
            self._RAC.log.debug( "{0}: Node is already turned on.".format(self._RAC.host) )
        self._RAC.log.debug("{0}: Turning on server.".format(self._RAC.host) )
        self._RAC.powerOn()

    def OFF( self ):
        status = self._RAC.powerStatus()
        if status == False:
            self._RAC.log.debug( "{0}: Node is already turned off".format(self._RAC.host) )
        self._RAC.log.debug("{0}: Turning off server.".format(self._RAC.host) )
        self._RAC.powerOff()

    def STATUS( self ):
        self._RAC.powerStatus()
        print self._RAC._STATUS



if __name__ == "__main__":
    
    state = raw_input( 'Type "On" or "Off": ' )
    cred = []
    cred.append( raw_input('Node IP: ') )
    cred.append( raw_input('Username: ') )
    cred.append( raw_input('Password: ') )
    print cred
    LOG = DEBUG()

    NODE = _RACInstance( LOG, ' '.join( cred ) )
    
    TELNET = Server( NODE )
    
    if state == 'On':
        TELNET.ON()

    if state == 'Off':
        TELNET.OFF()
