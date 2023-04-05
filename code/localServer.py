#!/usr/bin/env python3

import erlenberg.logHandler
logger = erlenberg.logHandler.Logger(erlenberg.logHandler.DEBUG, pp=True).start()

import utils.sshServer as sshServer
import utils.myUtils as myUtils
import socket
import utils.tcpServer as tcpServer
import json
import time
import subprocess

socket.setdefaulttimeout(300)

def get_ssh_server():
    allowed_users = [{'username': '',
                      'password': 'tunnel',
                      'pkey': 'AAAAC3NzaC1lZDI1NTE5AAAAIG6ruJUjErrnrRmTml7dbVCjVmGmhx5NYQq9cYKyO4ic'}]
                             
    host=('127.0.0.1', 2299)

    def ownServe(chan):
        global LOCALSERVERS
        chan.sendall(f'--- PYTHON CONSOLE ON LOCALSERVER {socket.gethostname().upper()} ---\r\n')
        myUtils.simpleShellServer(chan)
    
    server = sshServer.SshServer(
        host,
        sessionServe=ownServe, 
        allowedUsers=allowed_users, 
        allowPass=True, 
        allowPkey=True
    )
    return server

def server(remoteSock, localAddr):
    localSshSock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        while True:
            logger.info(f"sending offer to server")
            remoteSock.sendall("offer".encode())
            if (remoteSock.recv(1024).decode() == 'go'):
                remoteSock.sendall(socket.gethostname().encode())
            else:
                raise Exception("oops, something went wrong")
            logger.info(f"waiting for request from server")
            serverResponse = remoteSock.recv(1024).decode()
            if serverResponse == "request":
                logger.info(f"received request from server")
                break
            else:
                logger.error(f"expected request from server, got: {serverResponse}")

        """
        logger.info(f"connecting to local ssh server")
        localSshSock.connect(localAddr)
        logger.debug(f"successfully connected to local ssh server")
        """

        logger.info(f"sending go to remote server")
        remoteSock.sendall(b"go")

        #print(f"received: {remoteSock.recv(1024).decode()}")

        logger.debug(f"starting up ssh server")
        #myUtils.simpleShellServer(remoteSock)
        # -----------------------
        
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect(localAddr)
        #sock.connect(("127.0.0.1", 2299))
        myUtils.combinedForward(sock, remoteSock)

        """
        logger.info(f"connecting remote socket {utils.getSockName(remoteSock)} to local socket {utils.getSockName(localSshSock)}")
        utils.combinedForward(remoteSock, localSshSock)
        """
    finally:
        logger.debug(f"closing local socket")
        localSshSock.close()

def startOfProgram():
    addr = ("127.0.0.1", 2244)
    localAddr = ("127.0.0.1", 22)
    noWait=False

    try:
        #server_ssh = get_ssh_server()
        #server_ssh.start()
        while True:
            try:
                socket.setdefaulttimeout(300)
                remoteServer= socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                logger.info(f"start")
                logger.info(f"connecting to remote server")
                remoteServer.connect(addr)
                logger.info(f"connected to remote server")
                logger.debug(f"starting own server")
                server(remoteServer, localAddr)
            except KeyboardInterrupt:
                logger.info("Received Keyboard Interrupt")
                noWait=True
                break
            except:
                logger.critical(f"error")
            finally:
                logger.debug("closing remote socket")
                remoteServer.close()
                logger.info(f"shutdown")
                if not noWait:
                    time.sleep(1)
    finally:
        #server_ssh.stop()
        pass

def main():
    startOfProgram()

if __name__ == '__main__':
    main()
