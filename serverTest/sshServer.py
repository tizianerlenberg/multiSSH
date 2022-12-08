import socket, threading, paramiko, io

# own libraries
import logHandler
import server2
import internalSshServer
#import internalSshServer

logger = logHandler.getSimpleLogger(__name__, streamLogLevel=logHandler.DEBUG)

example_private_server_key = """
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACDj0suZTeZra8BnFbDCMeG7jooO8bVKfrv1Ef1lyDnpAQAAAKiUiBWalIgV
mgAAAAtzc2gtZWQyNTUxOQAAACDj0suZTeZra8BnFbDCMeG7jooO8bVKfrv1Ef1lyDnpAQ
AAAEDfykruhcysv0+nNm3fwFNVP5R31376Pg25J4cvhpi0EOPSy5lN5mtrwGcVsMIx4buO
ig7xtUp+u/UR/WXIOekBAAAAIHRpemlhbiBlcmxlbmJlcmdAREVTS1RPUC03OTBVMUpSAQ
IDBAU=
-----END OPENSSH PRIVATE KEY-----
"""[1:]

example_public_client_key = "AAAAC3NzaC1lZDI1NTE5AAAAIHou+d+/bDWQeNTENJN6rTULoB/SMUnf3jZ3ouc3jHIW"

example_allowed_users = [{'username': 'tunnel',
                         'password': None,
                         'pkey': example_public_client_key}]

class SshServer():
    def __init__(self, 
                 address, allowedUsers=example_allowed_users, 
                 serverKey=example_private_server_key, 
                 sessionServe=None, 
                 directTcpipServe=None,
                 allowPkey=True,
                 allowPass=False):

        host_key_file_obj = io.StringIO()
        host_key_file_obj.write(serverKey)
        host_key_file_obj.seek(0) 
        
        self.serverKey = paramiko.Ed25519Key(file_obj=host_key_file_obj)
        self.sessionServe=sessionServe
        self.directTcpipServe=directTcpipServe
        self.thosts = []
        self.chosts = []
        
        self.allowedUsers=allowedUsers
        for user in self.allowedUsers:
            if user['pkey']:
                user['pkey'] = paramiko.Ed25519Key(data=decodebytes(user['pkey'].encode()))
        
        self.allowSession= not not sessionServe
        self.allowDirectTcpip= not not directTcpipServe
        self.allowPkey=allowPkey
        self.allowPass=allowPass
        
        self.server = server2.Server(address, serve=self.serve)
        
    def serve(self, host):
        try:
            tran = paramiko.Transport(host[0])
            self.thosts.append(tran)
            tran.add_server_key(self.serverKey)
            iSshServer = internalSshServer.InternalSshServer(
                self.allowedUsers,
                allowSession=self.allowSession,
                allowDirectTcpip=self.allowDirectTcpip,
                allowPkey=self.allowPkey,
                allowPass=self.allowPass
            )
            try:
                tran.start_server(server=iSshServer)
            except paramiko.SSHException:
                logger.error(f"SSH negotiation failed.")
                raise

            # wait for auth
            chan = tran.accept(20)
            self.chosts.append(chan)
            if chan is None:
                logger.error(f"No channel")
                raise
            logger.debug(f"Authenticated")

            iSshServer.event.wait(10)
            if not iSshServer.event.is_set():
                logger.error(f"Client never asked for a shell")
                raise

            logger.debug("SshServerSocket started")
            chanInfo=iSshServer.chanInfo
            chanType=chanInfo['type']
            
            logger.debug(f"Channel of Type {chanType}")
            if chanType == 'session':
                self.sessionServe(chan)
            elif chanType == 'directTcpip':
                self.directTcpipServe(chan)
            else:
                logger.error(f"Channel type unknown")
                raise
            
        finally:
            logger.exception("")
            try:
                chan.close()
            except:
                logger.info(f"Could not close Channel")
            try:
                tran.close()
            except:
                logger.info(f"Could not close Transport")
    def start(self):
        self.server.start()
    def stop(self):
        for chost in self.chosts:
            try:
                logger.debug(f'Trying to close a channel')
                chost.close()
            except:
                logger.error(f'Closing channel failed')
        for thost in self.thosts:
            try:
                logger.debug(f'Trying to close a transport')
                thost.close()
            except:
                logger.error(f'Closing transport failed')
        try:
            logger.debug(f'Trying to stop server')
            self.server.stop()
        except:
            logger.error(f'Failed to stop server')
