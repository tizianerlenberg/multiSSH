#!/usr/bin/env python3

import threading
import socket
import time
import queue
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

def requestHandler(sock, addr, hosts, clients):
    logger.info("startet requestHandler")
    try:
        logger.info(f"sending host list to client: {addr}")
        sock.sendall(("\n".join(hosts.keys())).encode())
        request = sock.recv(1024).decode()
        request = request[9:]
        logger.info(f"received request for host: {request}")
        hostSock = hosts[request][0]
        logger.info(f"requesting connection from host: {request}")
        # TODO: See if host is closed
        try:
            hostSock.sendall(b"request")
            response = hostSock.recv(1024).decode()
        except:
            logger.exception("ERROR IN REQUEST_HANDLER: HOST UNREACHABLE")
            logger.info(f"closing unreachable host socket")
            hostSock.close()
            logger.info(f"closing client socket because requested host is not available")
            sock.close()
        else:
            if response == "go":
                logger.info(f"received ok from host: {request}")
                logger.info(f"sending go to client: {addr}")
                sock.sendall(b"go")
                logger.info(f"connecting client: {addr} with host: {request}")
                utils.combinedForward(sock, hostSock)
                clients[addr]=sock
    except:
        logger.exception("ERROR IN REQUEST_HANDLER")

def server(sock):
    waitingConnections= queue.Queue()
    connectedClients= {}
    availableHosts= {}
    try:
        logger.info(f"starting listener")
        threading.Thread(target=utils.listener, args=(sock, waitingConnections,)).start()
        while True:
            try:
                conn, msg= waitingConnections.get(block=False)
            except queue.Empty:
                pass
            else:
                logger.info(f"new {msg} from {conn[1]}")
                if msg.startswith("offer"):
                    availableHosts[msg[7:]] = conn
                elif msg.startswith("query"):
                    threading.Thread(target=requestHandler, args=(conn[0], conn[1], availableHosts, connectedClients,)).start()
            time.sleep(1)
    except:
        logger.exception(f"CRITICAL ERROR IN SERVER")
    finally:
        logger.info(f"cleaning up sockets")
        logger.info(f"cleaning up connected clients")
        for key, host in connectedClients.items():
            logger.info(f"closing client connection: {key}")
            host.close()
        logger.info(f"cleaning up queued clients")
        stop= False
        while(stop):
            try:
                conn= waitingConnections.get(block=False)
            except queue.Empty:
                stop= True
            else:
                logger.info(f"closing client connection: {conn[1]}")
                conn[0].close()
        logger.info(f"cleaning up connected hosts")
        for key, host in availableHosts.items():
            logger.info(f"closing host connection: {key}")
            host[0].close()

def startOfProgram():
    #addr = ("127.0.0.1", 2233)
    addr = ("0.0.0.0", 2233)

    while True:
        try:
            logger.info(f"start")
            logger.info(f"binding sockets")
            sock= socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.bind(addr)
            sock.listen()
            logger.info(f"starting server")
            server(sock)
        except:
            logger.exception(f"CRITICAL ERROR IN MAIN")
        finally:
            logger.info(f"shutdown")
            sock.close()
            time.sleep(1)

def main():
    startOfProgram()

if __name__ == '__main__':
    main()
