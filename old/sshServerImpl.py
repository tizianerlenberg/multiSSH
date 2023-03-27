import sshServer
import utils
import socket
import interactive

# own libraries
import logHandler

logger = logHandler.getSimpleLogger(__name__, streamLogLevel=logHandler.DEBUG)

############## Start ############## 

allowed_users = [{'username': '',
                  'password': 'tunnel',
                  'pkey': 'AAAAC3NzaC1lZDI1NTE5AAAAIGjPsR6iO6YxIsSg3Izl76RbTCjDiGZKqn9XRGM8GuVe'}]
                         
host=('127.0.0.1', 4446)

def ownServe(chan):
    chan.sendall('Hello there.\r\n')

def ownServe2(chan, chanInfo):
    src=chan
    dest = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    dest.connect(chanInfo['destination'])
    utils.combinedForward(src, dest)

def ownServe3(chan):
    interactive.interactive_shell(chan)

with sshServer.SshServer(
    host,
    sessionServe=ownServe,
    directTcpipServe=ownServe2, 
    allowedUsers=allowed_users, 
    allowPass=True, 
    allowPkey=True
) as serverObj:
    while True:
        pass
