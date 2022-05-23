#!/usr/bin/env python3

import threading
import socket
import time
import atexit
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

    try:
        while True:
            logger.info(f"sending offer to server")
            remoteSock.sendall(("offer: " + socket.gethostname()).encode())
            logger.info(f"waiting for request from server")
            serverResponse = remoteSock.recv(1024).decode()
            if serverResponse == "request":
                logger.info(f"received request from server")
                break
            else:
                logger.error(f"expected request from server, got: {serverResponse}")

        logger.info(f"connecting to local ssh server")
        localSshSock.connect(localAddr)
        logger.debug(f"successfully connected to local ssh server")

        logger.info(f"sending go to remote server")
        remoteSock.sendall(b"go")
        logger.info(f"connecting remote socket {utils.getSockName(remoteSock)} to local socket {utils.getSockName(localSshSock)}")
        utils.combinedForward(remoteSock, localSshSock)
    finally:
        logger.debug(f"closing local socket")
        localSshSock.close()

def startOfProgram():
    addr = ("127.0.0.1", 2233)
    #addr = ("192.52.45.151", 2233)
    localAddr = ("127.0.0.1", 22)

    while True:
        try:
            remoteServer= socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            logger.info(f"start")
            logger.info(f"connecting to remote server")
            remoteServer.connect(addr)
            logger.info(f"connected to remote server")
            logger.debug(f"starting own server")
            server(remoteServer, localAddr)
        except:
            logger.critical(f"error")
            logger.exception("")
        finally:
            logger.debug("closing remote socket")
            remoteServer.close()
            logger.info(f"shutdown")
            time.sleep(1)

def main():
    startOfProgram()

if __name__ == '__main__':
    main()
