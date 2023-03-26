#!/usr/bin/env python3

import erlenberg.logHandler
logger = erlenberg.logHandler.Logger(erlenberg.logHandler.DEBUG, pp=True).start()

import utils.sshServer as sshServer
import utils.utils as utils
import socket

############## Start ############## 

allowed_users = [{'username': '',
                  'password': 'tunnel',
                  'pkey': 'AAAAC3NzaC1lZDI1NTE5AAAAIGjPsR6iO6YxIsSg3Izl76RbTCjDiGZKqn9XRGM8GuVe'}]
                         
host=('127.0.0.1', 4446)

def ownServe(chan):
    chan.sendall('Hello there.\r\n')

def ownServe2(chan, chanInfo):
    src=chan
    dest = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    dest.connect(chanInfo['destination'])
    utils.combinedForward(src, dest)

with sshServer.SshServer(
    host,
    sessionServe=ownServe,
    directTcpipServe=ownServe2, 
    allowedUsers=allowed_users, 
    allowPass=True, 
    allowPkey=True
) as serverObj:
    while True:
        pass
