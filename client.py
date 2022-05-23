#!/usr/bin/env python3

import threading
import socket
import time
import logging

# own libraries
import utils
import logHandler

logger = logging.getLogger(__name__)
# don't change log level here! change it in logHandler.py instead
logger.setLevel(logging.DEBUG)

logger.addHandler(logHandler.stream_handler)
logger.addHandler(logHandler.file_handler)

# ------------------------------------------------------------------------------

def server(remoteSock, localAddr):
    localSshSock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    logger.info(f"sending query to server")
    remoteSock.sendall(b"query")
    logger.info(f"waiting for host list from server")
    availableHosts = remoteSock.recv(1024).decode()
    availableHosts = availableHosts.split("\n")
    myChoice = utils.selectFrom(availableHosts)
    logger.info(f"got user input")

    logger.info(f"sending request to server")
    remoteSock.sendall(("request: " + myChoice).encode())

    logger.info(f"waiting for go from remote server")
    ack = remoteSock.recv(1024).decode()
    if ack == "go":
        logger.info(f"received go from server")
        try:
            logger.info(f"binding to local socket")
            localSshSock.bind(localAddr)
            localSshSock.listen(1)
            logger.info(f"waiting for connections to local socket")
            conn = localSshSock.accept()[0]
            logger.info(f"received connection to local socket")
            logger.info(f"starting forward")
            utils.combinedForward(conn, remoteSock)
        except:
            logger.exception("Exception while trying to start forward")
        finally:
            logger.info("closing local socket")
            localSshSock.close()

    else:
        logger.error("did not receive go from server, shutting down")

def startOfProgram():
    #addr = ("127.0.0.1", 2233)
    addr = ("192.52.45.151", 2233)
    #localAddr = ("0.0.0.0", 2222)
    localAddr = ("127.0.0.1", 2222)

    try:
        logger.info(f"start")
        logger.info(f"connecting to remote server")
        sock= socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect(addr)
        logger.info(f"connected to remote server")
        logger.info(f"starting own server")
        server(sock, localAddr)
    except:
        logger.exception(f"CRITICAL ERROR IN MAIN")
    finally:
        logger.info("closing remote socket")
        sock.close()
        logger.info(f"shutdown")

def main():
    startOfProgram()

if __name__ == '__main__':
    main()
