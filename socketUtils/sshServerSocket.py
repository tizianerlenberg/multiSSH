import socket
import queue
import threading
import enum
import io
import paramiko
import base64
from paramiko.py3compat import b, u, decodebytes
from binascii import hexlify
import paramikoClient

# own libraries
import logHandler

logger = logHandler.getSimpleLogger(__name__, streamLogLevel=logHandler.DEBUG, fileLogLevel=logHandler.DEBUG)

example_private_server_key = """-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACDj0suZTeZra8BnFbDCMeG7jooO8bVKfrv1Ef1lyDnpAQAAAKiUiBWalIgV
mgAAAAtzc2gtZWQyNTUxOQAAACDj0suZTeZra8BnFbDCMeG7jooO8bVKfrv1Ef1lyDnpAQ
AAAEDfykruhcysv0+nNm3fwFNVP5R31376Pg25J4cvhpi0EOPSy5lN5mtrwGcVsMIx4buO
ig7xtUp+u/UR/WXIOekBAAAAIHRpemlhbiBlcmxlbmJlcmdAREVTS1RPUC03OTBVMUpSAQ
IDBAU=
-----END OPENSSH PRIVATE KEY-----
"""

example_public_client_key = "AAAAC3NzaC1lZDI1NTE5AAAAIHou+d+/bDWQeNTENJN6rTULoB/SMUnf3jZ3ouc3jHIW"

class SshServer(paramiko.ServerInterface):
    def __init__(self, client_username='tunnel', client_key=None, client_pass=None):
        self.event = threading.Event()
        self.client_key = client_key
        self.client_pass = client_pass
        self.client_username = client_username

    def check_channel_request(self, kind, chanid):
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        if kind == "direct-tcpip":
            return paramiko.OPEN_SUCCEEDED
        logger.error(f"\"{kind}\" session is not supported")
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_password(self, username, password):
        if (username == self.client_username) and (password == self.client_pass):
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def check_auth_publickey(self, username, key):
        logger.debug(f"Auth attempt with key: {u(hexlify(key.get_fingerprint()))}")
        if (username == self.client_username) and (key == self.client_key):
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def get_allowed_auths(self, username):
        answer=''
        if not not self.client_pass:
            answer= 'password'
        if not not self.client_key:
            if answer == '':
                answer= 'publickey'
            else:
                answer=answer + ',publickey'
        return answer

    def check_channel_shell_request(self, channel):
        self.event.set()
        return True

    def check_channel_pty_request(
        self, channel, term, width, height, pixelwidth, pixelheight, modes
    ):
        return True
    
    def check_channel_direct_tcpip_request(
        self, chanid, origin, destination
    ):
        logger.info(f"chanid: {chanid}, origin: {origin}, destination: {destination}")
        self.event.set()
        return paramiko.OPEN_SUCCEEDED

class SshServerSocket():
    def __init__(self, sock, hostname='tunnel', username='tunnel', host_key=example_private_server_key, client_key=example_public_client_key, password=None):
        logger.debug(f"SshClientSocket initialisation started")
        self.sock=sock
        self.hostname=hostname
        self.username=username
        self.host_key=host_key
        self.client_key=client_key
        self.password=password
        self.chan = None
        self.tran = None
        self.client = None

        host_key_file_obj = io.StringIO()
        host_key_file_obj.write(self.host_key)
        host_key_file_obj.seek(0)
        self.host_key_obj = paramiko.Ed25519Key(file_obj=host_key_file_obj)

        self.client_key_obj = paramiko.Ed25519Key(data=decodebytes(self.client_key.encode()))
        logger.debug(f"SshClientSocket initialized")

    def start(self):
        try:
            self.tran = paramiko.Transport(self.sock)
            self.tran.add_server_key(self.host_key_obj)
            server = SshServer(client_key=self.client_key_obj, client_pass=self.password)
            try:
                self.tran.start_server(server=server)
            except paramiko.SSHException:
                logger.error(f"SSH negotiation failed.")
                return 1

            # wait for auth
            self.chan = self.tran.accept(20)
            if self.chan is None:
                logger.error(f"No channel")
                return 1
            logger.debug(f"Authenticated")

            server.event.wait(10)
            if not server.event.is_set():
                logger.error(f"Client never asked for a shell")
                return 1

            logger.debug("SshServerSocket started")
            return 0

        except:
            logger.exception("")
            try:
                self.tran.close()
            except:
                pass
            return 1

    def close(self):
        try:
            logger.debug(f"Closing Channel")
            self.chan.close()
        except:
            logger.info(f"Error closing Channel")
        try:
            logger.debug(f"Closing Transport")
            self.tran.close()
        except:
            logger.info(f"Error closing Transport")

def main():
    sock = SshServerSocket()

if __name__ == '__main__':
    main()
