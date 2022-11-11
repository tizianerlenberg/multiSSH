#!/usr/bin/env python3

import threading
import socket
import time

# own libraries
import utils
import logHandler
import config

logger = logHandler.getSimpleLogger(__name__, streamLogLevel=logHandler.DEBUG, fileLogLevel=logHandler.DEBUG)

socket.setdefaulttimeout(300)

# ------------------------------------------------------------------------------

def server(remoteSock, localAddr):
    localSshSock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        logger.info(f"sending query to server")
        remoteSock.sendall(b"query")
        logger.info(f"waiting for host list from server")
        availableHosts = remoteSock.recv(1024).decode()
        if availableHosts == "EMPTY":
            raise Exception("No hosts available")
        availableHosts = availableHosts.split("\n")
        myChoice = utils.selectFrom(availableHosts)
        logger.debug(f"got user input")

        logger.info(f"sending request to server")
        remoteSock.sendall(("request: " + myChoice).encode())

        logger.debug(f"waiting for go from remote server")
        ack = remoteSock.recv(1024).decode()
        if ack == "go":
            logger.info(f"received go from server")
            try:
                logger.debug(f"sending message to server")
                remoteSock.sendall(b"connection established")
                logger.debug(f"starting up shell")
                utils.simpleShellClient(remoteSock)

            except KeyboardInterrupt:
                raise
            except:
                logger.error("Exception while trying to start forward")
                logger.exception("")
            finally:
                logger.debug("closing local socket")
                localSshSock.close()

        else:
            logger.warning("did not receive go from server, shutting down")
    except KeyboardInterrupt:
        raise
    except:
        raise

def startOfProgram():
    addr = config.serverAddress
    localAddr = config.clientAddress

    try:
        socket.setdefaulttimeout(300)
        logger.info(f"start")
        logger.info(f"connecting to remote server")
        sock= socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect(addr)
        logger.info(f"connected to remote server")
        logger.info(f"starting own server")
        server(sock, localAddr)
    except KeyboardInterrupt:
        logger.info("Received Keyboard Interrupt")
    except:
        logger.critical(f"error in main")
        logger.exception("")
    finally:
        logger.debug("closing remote socket")
        sock.close()
        logger.info(f"shutdown")

def main():
    startOfProgram()

if __name__ == '__main__':
    main()
