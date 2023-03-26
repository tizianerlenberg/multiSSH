#!/usr/bin/env python3

import threading
import socket
import time
import queue

# own libraries
import utils
import logHandler
import config

logger = logHandler.getSimpleLogger(__name__, streamLogLevel=logHandler.DEBUG, fileLogLevel=logHandler.DEBUG)

socket.setdefaulttimeout(300)

# ------------------------------------------------------------------------------

def requestHandler(sock, addr, hosts, clients):
    logger.debug("started requestHandler")
    try:
        logger.info(f"sending host list to client: {addr}")
        if hosts:
            sock.sendall(("\n".join(hosts.keys())).encode())
        else:
            sock.sendall(b"EMPTY")
            raise Exception("No hosts available")
        request = sock.recv(1024).decode()
        request = request[9:]
        logger.info(f"received request for host: {request}")
        logger.debug("searching host dictonary")
        hostSock = hosts[request][0]
        logger.info(f"requesting connection from host: {request}")
        try:
            hostSock.sendall(b"request")
            response = hostSock.recv(1024).decode()
        except:
            logger.warning("error in request handler: host unreachable")
            logger.exception("")
            logger.debug(f"closing unreachable host socket")
            hostSock.close()
            logger.debug(f"closing client socket because requested host is not available")
            sock.close()
        else:
            if response == "go":
                logger.info(f"received ok from host: {request}")
                logger.info(f"sending go to client: {addr}")
                sock.sendall(b"go")
                clients[addr]=sock
                logger.info(f"connecting client: {addr} with host {request}: {utils.getSockName(hostSock)}")
                utils.combinedForward(sock, hostSock)
    except:
        logger.warning("error in request handler")
        logger.exception("")

def server(sock):
    waitingConnections= queue.Queue()
    connectedClients= {}
    availableHosts= {}
    listnerIsDown= utils.LockedVar(False)

    try:
        logger.info(f"starting listener")
        threading.Thread(target=utils.listener, args=(sock, waitingConnections, listnerIsDown,)).start()
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

            if listnerIsDown.get():
                logger.critical("Listener is down")
                raise Exception("Listener is down")

            for key in list(availableHosts.keys()).copy():
                if availableHosts[key][0]._closed:
                    logger.warning(f"Host {key}, {availableHosts[key][1]} is down, removing from available hosts")
                    availableHosts.pop(key)

            if sock._closed:
                logger.critical("Socket has closed unexpectedly")
                raise Exception("Socket has closed unexpectedly")

            time.sleep(1)

    except KeyboardInterrupt:
        raise
    except:
        logger.critical(f"error")
        logger.exception("")
    finally:
        logger.info(f"cleaning up sockets")
        logger.debug(f"cleaning up connected clients")
        for key, host in connectedClients.items():
            logger.debug(f"closing client connection: {key}")
            host.close()
        logger.debug(f"cleaning up queued clients")
        stop= False
        while(stop):
            try:
                conn= waitingConnections.get(block=False)
            except queue.Empty:
                stop= True
            else:
                logger.debug(f"closing client connection: {utils.getSockName(conn[0])}")
                conn[0].close()
        logger.debug(f"cleaning up connected hosts")
        for key, host in availableHosts.items():
            logger.debug(f"closing host {key}, connection: {utils.getSockName(host[0])}")
            host[0].close()

def startOfProgram():
    addr = config.serverAddress
    noWait=False

    while True:
        try:
            socket.setdefaulttimeout(300)
            logger.info(f"starting")
            logger.info(f"binding sockets")
            sock= socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.bind(addr)
            sock.listen()
            logger.info(f"starting server")
            server(sock)
        except KeyboardInterrupt:
            logger.info("Received Keyboard Interrupt")
            noWait=True
            break
        except:
            logger.critical(f"error in main")
            logger.exception("")
        finally:
            logger.info(f"shutdown")
            sock.close()
            if not noWait:
                time.sleep(1)
            logger.info("shutdown successfull")

def main():
    startOfProgram()

if __name__ == '__main__':
    main()
