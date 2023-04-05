#!/usr/bin/env python3

import erlenberg.logHandler
logger = erlenberg.logHandler.Logger(erlenberg.logHandler.DEBUG, pp=True).start()

import utils.sshServer as sshServer
import utils.myUtils as myUtils
import socket
import utils.tcpServer as tcpServer
import json

socket.setdefaulttimeout(300)

########## GLOBALS ##########

LOCALSERVERS = {}
CONNS = 0

########## FUNCTIONS ##########

# TODO

########## SSH SERVER ##########

def get_ssh_server():
    global LOCALSERVERS
    allowed_users = [{'username': '',
                      'password': 'tunnel',
                      'pkey': 'AAAAC3NzaC1lZDI1NTE5AAAAIG6ruJUjErrnrRmTml7dbVCjVmGmhx5NYQq9cYKyO4ic'}]
                             
    host=('127.0.0.1', 2233)

    def ownServe(chan):
        global LOCALSERVERS
        chan.sendall('These localServers are available:\r\n')
        chan.sendall('--- START JSON DUMP ---\r\n')
        chan.sendall(json.dumps(list(LOCALSERVERS.keys()), indent=2).replace("\n", "\r\n")  + '\r\n')
        chan.sendall('--- END JSON DUMP ---\r\n')

    def ownServe2(chan, chanInfo):
        global LOCALSERVERS
        src=chan
        #dest = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        #dest.connect(chanInfo['destination'])
        #utils.combinedForward(src, dest)
        logger.debug("destination is: " + str(chanInfo['destination']))
        requestedDest = chanInfo['destination'][0].lower()
        dest = LOCALSERVERS[requestedDest]
        dest.sendall(b'request')
        resp = dest.recv(2).decode()
        if (resp == 'go'):
            myUtils.combinedForward(src, dest)
            logger.debug('NOW AFTER FORWARD')
            while True:
                pass
        else:
            logger.info(f"response was: {resp}")
            raise Exception('oops, protocoll error')

    server = sshServer.SshServer(
        host,
        sessionServe=ownServe,
        directTcpipServe=ownServe2, 
        allowedUsers=allowed_users, 
        allowPass=True, 
        allowPkey=True
    )
    return server

########## BACKEND SERVER ##########

def get_backend_server():
    global LOCALSERVERS
    global CONNS
    def ownServe(sockT):
        global LOCALSERVERS
        global CONNS
        sock = sockT[0]
        if (sock.recv(1024).decode() == 'offer'):
            sock.sendall(b'go')
            resp = sock.recv(1024).decode().lower()
            print(f"hostname is: {resp}")
            LOCALSERVERS[resp] = sock
            #LOCALSERVERS[f"conn{CONNS}"] = sock
            #CONNS = CONNS + 1
            while True:
                pass
        else:
            sock.close()

    host=('127.0.0.1', 2244)
        
    server = tcpServer.Server(host, serve=ownServe)
    return server

########## START SERVERS ##########

def main():
    try:
        server_backend = get_backend_server()
        server_ssh = get_ssh_server()
        server_backend.start()
        server_ssh.start()
        while True:
            pass
    finally:
        try:
            server_backend.stop()
        except:
            pass
        try:
            server_ssh.stop()
        except:
            pass

if __name__ == '__main__':
    main()
