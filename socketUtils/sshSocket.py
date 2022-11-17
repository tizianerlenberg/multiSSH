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

example_host_key = """***REMOVED: example key, purged from git history***
"""

new_host_key= """***REMOVED: example key, purged from git history***
"""
new_client_key= "AAAAC3NzaC1lZDI1NTE5AAAAIHou+d+/bDWQeNTENJN6rTULoB/SMUnf3jZ3ouc3jHIW"

example_client_key = "AAAAB3NzaC1yc2EAAAADAQABAAACAQDBgsFOvSmvmBiBbfbhtWp/ei4OhY2f+984kVucKkjGBFzebO+xriYGnhT++yfrYfL1s6pIFhg5EnOoBXl8cLAHL0l5WSsukc4jSGKtWZU3EjsLebuL83GKBvuLSacv4caiuMtIM9FKKA2HnKkPi3MVRZSNYuxqPjOkxrQpnGCkqwW8LAHUNTYnDHMFLXY/NAgEYVCwdg+bQga2xKhNUqGZZoMwr5200UWQZgpYgUuQ3fFTsFf4ReOimN7WqbXNKJ7e/8t3p+6pcA8YDLWt9pSXCZEq/Q5NAow0/dsY/BHXHcetHafJlDVi8iMtfZ+qAIBuJoUL642tRRQAfp/26ujtXvnw7Ol8CSkTMdx69sMkHuBwx6Hn3rBQc4+13luwh9Bry/quM06pV2Z94DSTG53Bg1JQugcV81sjrlAJB3y2sNeaLfC2sQAp1YYa5XPB/vi0/WBpgRe8FnDCS5BxO5mJLkc5/LcyenUpYIgHYVwsQiO8OBBEQrwNXsGsDky985gGa4zCEmAZP5L23sX7voCeINvDHpKmJ2gkqxxi2f3AT0N6QToo9ipZHwifDmUdGnBIEtWCBGqDzkyT29sIM+QNYXpWNm43pz+mwN/bb8uWKDoE9dKmDRc6EwYS5XUPc1d/WZDPviRXLQ4fRnWQWmHjCyUoRaaqsUzeENPHu65IxQ=="

class SshServer(paramiko.ServerInterface):
    def __init__(self, client_username='tunnel', client_key=None, client_pass=None):
        self.event = threading.Event()
        self.client_key = client_key
        self.client_pass = client_pass
        self.client_username = client_username

    def check_channel_request(self, kind, chanid):
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_password(self, username, password):
        if (username == self.client_username) and (password == self.client_pass):
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def check_auth_publickey(self, username, key):
        print("Auth attempt with key: " + u(hexlify(key.get_fingerprint())))
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

def getSockName(sock):
    try:
        try:
            peer=sock.getpeername()
        except:
            return f"{sock.getsockname()}"
        else:
            return f"[{sock.getsockname()} connected to {peer}]"
    except:
        return "[some socket (closed)]"

class SshSocket():
    def __init__(self, sock, username='tunnel', host_key=new_host_key, client_key=new_client_key, password=None):
        logger.debug(f"SshSocket initialisation started")
        self.sock=sock
        self.username=username
        self.host_key=host_key
        self.client_key=client_key
        self.password=password
        self.chan = None
        self.tran = None
        self.client = None

        host_key_file_obj = io.StringIO()
        host_key_file_obj.write(new_host_key)
        host_key_file_obj.seek(0)
        self.host_key_obj = paramiko.Ed25519Key(file_obj=host_key_file_obj)

        self.client_key_obj = paramiko.Ed25519Key(data=base64.decodebytes(client_key.encode()))
        logger.debug(f"SshSocket initialized")

    def start_server(self):
        try:
            self.tran = paramiko.Transport(self.sock)
            self.tran.add_server_key(self.host_key_obj)
            server = SshServer(client_key=self.client_key_obj)
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

            logger.debug("SshServer started, returning opened channel")
            return self.chan

        except:
            logger.exception("")
            try:
                self.tran.close()
            except:
                pass
            return 1
    def start_client(self):
        self.client = paramiko.client.SSHClient()

        #keydata = b"AAAAB3NzaC1yc2EAAAADAQABAAABAQDCbjl1z4l8DdPwlmXQQPLwqxba1+QxffwAJHWbDI4cbK1VQdpMoI/kByryJf0rxplJS3t/rfG7L5yd1DH/0wQwfxS5AzYx/q6L+kuACfDoVQAevdbMC1qEYAMapJ6LhWK4wknk/1h/LqkHdcq3DiDR8KUseLXbN+XeuioC3xvQXWHoPlzJbSyk5X1xfSLUhV2/nRUUdGU0MRROoTi+7FVM4tvjAQKQjoNO4avfQtyeaRa+DkkGaWk/TqBchtTdhoEfh0e6dSWgKZsRVzP25+fKJoFnEVi50Hm/5JAC0RuYBdw3YdTUudPaqGSy0PhASlAiWgM+wWaB68Kd4B1U8uHP"
        keydata = b"AAAAC3NzaC1lZDI1NTE5AAAAIOPSy5lN5mtrwGcVsMIx4buOig7xtUp+u/UR/WXIOekB"
        key = paramiko.Ed25519Key(data=decodebytes(keydata))
        self.client.get_host_keys().add('', 'ssh-ed25519', key)
        new_key = """***REMOVED: example key, purged from git history***"""

        key_file_obj = io.StringIO()
        key_file_obj.write(new_key)
        key_file_obj.seek(0)
        myKey = paramiko.Ed25519Key(file_obj=key_file_obj)

        self.client.connect('', username=self.username, password=self.password, sock=self.sock, pkey=myKey)
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
    sock = SshSocket()

if __name__ == '__main__':
    main()
