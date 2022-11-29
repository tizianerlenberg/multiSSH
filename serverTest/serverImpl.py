import server2

# own libraries
import logHandler

logger = logHandler.getSimpleLogger(__name__, streamLogLevel=logHandler.DEBUG)

def ownServe(host):
    while True:
        answer = host[0].recv(1024)
        if answer == b'':
            raise
        logger.info(f"[{host[1]}] {answer.decode()}")

serverObj = server2.Server(('127.0.0.1', 4445), ownServe)
serverObj.start()
try:
    while True:
        pass
finally:
    serverObj.stop()
