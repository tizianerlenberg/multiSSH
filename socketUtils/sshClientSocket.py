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

example_private_client_key = """-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACB6Lvnfv2w1kHjUxDSTeq01C6Af0jFJ3942d6LnN4xyFgAAAKijEH/3oxB/
9wAAAAtzc2gtZWQyNTUxOQAAACB6Lvnfv2w1kHjUxDSTeq01C6Af0jFJ3942d6LnN4xyFg
AAAEDt7rQCg/uYx3gRFcWgbOdOMEnutsL3nOdiZC36n2tcZnou+d+/bDWQeNTENJN6rTUL
oB/SMUnf3jZ3ouc3jHIWAAAAIHRpemlhbiBlcmxlbmJlcmdAREVTS1RPUC03OTBVMUpSAQ
IDBAU=
-----END OPENSSH PRIVATE KEY-----"""

example_public_server_key = "AAAAC3NzaC1lZDI1NTE5AAAAIOPSy5lN5mtrwGcVsMIx4buOig7xtUp+u/UR/WXIOekB"

class SshClientSocket():
    def __init__(self, sock, hostname='tunnel', username='tunnel', host_key=example_public_server_key, client_key=example_private_client_key, password=None):
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

        client_key_file_obj = io.StringIO()
        client_key_file_obj.write(self.client_key)
        client_key_file_obj.seek(0)
        self.client_key_obj = paramiko.Ed25519Key(file_obj=client_key_file_obj)

        self.host_key_obj = paramiko.Ed25519Key(data=decodebytes(self.host_key.encode()))
        logger.debug(f"SshClientSocket initialized")

    def start_client(self):
        self.client = paramiko.client.SSHClient()

        self.client.get_host_keys().add(self.hostname, 'ssh-ed25519', self.host_key_obj)

        self.client.connect(self.hostname, username=self.username, password=self.password, sock=self.sock, pkey=self.client_key_obj)
        self.tran = self.client.get_transport()

        self.chan = self.tran.open_session()
        term='vt100'
        width=80
        height=24
        width_pixels=0
        height_pixels=0

        self.chan.get_pty(term, width, height, width_pixels, height_pixels)
        self.chan.invoke_shell()
        
        return self.chan

    def close(self):
        self.chan.close()
        self.tran.close()

def main():
    sock = SshClientSocket()

if __name__ == '__main__':
    main()
