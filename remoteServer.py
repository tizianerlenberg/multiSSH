#!/usr/bin/env python3

import threading
import socket
import time
import queue
import utils
import logging

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

formatter = logging.Formatter('[%(name)s] %(message)s')

#file_handler = logging.FileHandler('sample.log')
#file_handler.setLevel(logging.ERROR)
#file_handler.setFormatter(formatter)

stream_handler = logging.StreamHandler()
stream_handler.setFormatter(formatter)

#logger.addHandler(file_handler)
logger.addHandler(stream_handler)

#-------------------------------------------------------------------------------

def requestHandler(sock, addr, hosts, clients):
    logger.info(f"sending host list to client: {addr}")
    sock.sendall(("\n".join(hosts.keys())).encode())
    request = sock.recv(1024).decode()
    request = request[9:]
    logger.info(f"received request for host: {request}")
    hostSock = hosts[request]

    logger.info(f"requesting connection from host: {request}")
    hostSock.sendall(b"request")
    response = hostSock.recv(1024).decode()
    if response == "go":
        logger.info(f"received ok from host: {request}")
        logger.info(f"sending go to client: {addr}")
        sock.sendall(b"go")
        logger.info(f"connecting client: {addr} with host: {request}")
        utils.combinedForward(sock, hostSock)
        clients[addr]=sock

def listener(sock, waitingConnections):
    pass

def server(sock):
    waitingConnections= queue.Queue()
    connectedClients= {}
    availableHosts= {}
    try:
        logger.info(f"starting listener")
        listener(sock, waitingConnections)
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
                    requestHandler(conn[0], conn[1], availableHosts, connectedClients)
            logger.info(f"nothing to do")
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
            host.close()

def startOfProgram():
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
