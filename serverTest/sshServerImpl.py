import sshServer

# own libraries
import logHandler

logger = logHandler.getSimpleLogger(__name__, streamLogLevel=logHandler.DEBUG)

example_allowed_users = [{'username': 'tunnel',
                         'password': 'tunnel',
                         'pkey': None}]

def ownServe(chan):
    while True:
        answer = chan.recv(1024)
        if answer == b'':
            raise
        logger.info(f"{answer}")

serverObj = sshServer.SshServer(('127.0.0.1', 4446), sessionServe=ownServe, allowedUsers=example_allowed_users, allowPkey=False, allowPass=True)

try:
    serverObj.start()
    while True:
        pass
finally:
    serverObj.stop()
