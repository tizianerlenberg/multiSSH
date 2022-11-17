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

example_host_key = """-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAwm45dc+JfA3T8JZl0EDy8KsW2tfkMX38ACR1mwyOHGytVUHa
TKCP5Acq8iX9K8aZSUt7f63xuy+cndQx/9MEMH8UuQM2Mf6ui/pLgAnw6FUAHr3W
zAtahGADGqSei4ViuMJJ5P9Yfy6pB3XKtw4g0fClLHi12zfl3roqAt8b0F1h6D5c
yW0spOV9cX0i1IVdv50VFHRlNDEUTqE4vuxVTOLb4wECkI6DTuGr30LcnmkWvg5J
BmlpP06gXIbU3YaBH4dHunUloCmbEVcz9ufnyiaBZxFYudB5v+SQAtEbmAXcN2HU
1LnT2qhkstD4QEpQIloDPsFmgevCneAdVPLhzwIDAQABAoIBAC35tHqoNaFw/6HP
XontIcVJH6FmFZ6iZNl/xZOBV4VfKWmUpdMi0IOiMkSKOSCF2K9dOvnJHvUdYBJu
H9iXhFEXa8YH/WO7DnkpGXtQXngByYJ7b3RWZvQQZAuDy73AL8TypFiTDNEeLngG
IYZBv/8EwXoPnSkWQbP2H4MIUOJnGNkIYtJkZ7L1ui3xUaT467eY10mGlGoz8Vf+
xsolKWIe8+Cr6vO7UEVFq3lN0M62/9W7cIgEWcPurDzAgi7nQt2QfMPysvf3+/Bx
lDcOAvqiKg79xfLW74xGjDdpdEwJGyEP6jMC496dOFxt06t+jU+Z+YHz6twc9qkm
ObJ56NECgYEA0y3fCfUgl70EL9oVqx0jYK2ngLetsPQVPo+O1p7ngEcCfpbzi3Fc
EY+wJZM/K+gkFf9FeYLLfjgY3Qb1L1tzQieTXiAeOFFnkDsh5XY9IzSYKRkKQ0Q+
W1hrS3zz6knVDPk1e8OIpYzv5VyjFT3BB3SSqaDkOmvqEIlJWPSJGscCgYEA67JX
EPhsVI6WCerNUOyVCdS+9/OM3vTbd3SAZ9NWQ3/h80hBrDAPE498k3rTTadBtNwi
fVshRE95jje0yMDoSHQbMKUznCuSlXW6D8SsYuDVDYCx+iz8nMpB+CecNdtPAQ/3
y63xST0AbEd1GZWe5Pcz0GzC8U9INC9NdPTlOLkCgYBASOByeYo4ZrOVlX+vHSmd
zn8E8eUPzt2As9a5gpnaNMOPoYf11MZAGkt2xMIgLYR+pbySZrxnadA3yFxu1Bnb
84wqxQAuCKnMABQrc7jctK/1Isg6/dU1nU7cJediVKNkVaBwUm+QZbzJR0/lsWzH
Rjc3J+ER37Pa4M/RIm9yFQKBgQCxlDd3CMSN3LP8mtTAUM9ljc2oAO61GOS1lqgc
EaVfy90QL/OS6M6jHStt7k9/pTGjM2wk6GEjF4Hs/dmOm5Em7ZuCxiUhV87kHsPl
l3eOM/kxaDIv3G8jLlwPvMA775URptc6tT4iwPwtmJUIhqsltX5rXVZu+x3ae30v
TkfZuQKBgQCu0Q6eKXuIrLwZsOcHFZ46GHrQnZcBQWbWCUSVuy7Gd9kslfb1F2FA
6O61JuEYOIJI+f80/6NuoPglxljQVwSed0aHstnDa9acd3OZ9KKhpeJzPVTCCd/P
GS8i9iadnOnUwhh/pAfPWBcUL9KZ7D3LFP2e4tx3ti9MjA4E03jaiQ==
-----END RSA PRIVATE KEY-----
"""

new_host_key= """-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACDj0suZTeZra8BnFbDCMeG7jooO8bVKfrv1Ef1lyDnpAQAAAKiUiBWalIgV
mgAAAAtzc2gtZWQyNTUxOQAAACDj0suZTeZra8BnFbDCMeG7jooO8bVKfrv1Ef1lyDnpAQ
AAAEDfykruhcysv0+nNm3fwFNVP5R31376Pg25J4cvhpi0EOPSy5lN5mtrwGcVsMIx4buO
ig7xtUp+u/UR/WXIOekBAAAAIHRpemlhbiBlcmxlbmJlcmdAREVTS1RPUC03OTBVMUpSAQ
IDBAU=
-----END OPENSSH PRIVATE KEY-----
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
        new_key = """-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACB6Lvnfv2w1kHjUxDSTeq01C6Af0jFJ3942d6LnN4xyFgAAAKijEH/3oxB/
9wAAAAtzc2gtZWQyNTUxOQAAACB6Lvnfv2w1kHjUxDSTeq01C6Af0jFJ3942d6LnN4xyFg
AAAEDt7rQCg/uYx3gRFcWgbOdOMEnutsL3nOdiZC36n2tcZnou+d+/bDWQeNTENJN6rTUL
oB/SMUnf3jZ3ouc3jHIWAAAAIHRpemlhbiBlcmxlbmJlcmdAREVTS1RPUC03OTBVMUpSAQ
IDBAU=
-----END OPENSSH PRIVATE KEY-----"""

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
