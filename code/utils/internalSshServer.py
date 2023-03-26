#!/usr/bin/env python3

import erlenberg.logHandler
logger = erlenberg.logHandler.Logger(erlenberg.logHandler.DEBUG, pp=True).start()

import socket
import queue
import threading
import enum
import io
import paramiko
import base64
#from paramiko.py3compat import b, u, decodebytes
# patch for u() missing since py3compat is obsolete
def u(obj):
    return obj.decode("utf8")

from base64 import decodebytes
from binascii import hexlify

class InternalSshServer(paramiko.ServerInterface):
    def __init__(self, allowedUsers, 
                 allowPkey=True, 
                 allowPass=False, 
                 allowSession=True, 
                 allowDirectTcpip=True):
        self.event = threading.Event()

        self.allowedUsers=allowedUsers
        self.allowPkey=allowPkey
        self.allowPass=allowPass
        self.allowSession=allowSession
        self.allowDirectTcpip=allowDirectTcpip

        self.chanInfo={}

    def check_channel_request(self, kind, chanid):
        if kind == "session":
            if self.allowSession:
                return paramiko.OPEN_SUCCEEDED
        if kind == "direct-tcpip":
            if self.allowDirectTcpip:
                return paramiko.OPEN_SUCCEEDED
        logger.error(f"\"{kind}\" session is not supported")
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_password(self, username, password):
        if not self.allowPass:
            logger.warning('Attempted password auth, but is not allowed')
            return paramiko.AUTH_FAILED
        logger.debug(f"User {username} tries to authenticate with password {password}")
        for user in self.allowedUsers:
            if ((user['username'] == '') or (user['username'] == username)) and (user['password'] == password):
                logger.debug(f"User {username} authenticated successfully")
                return paramiko.AUTH_SUCCESSFUL
        logger.warning(f"User {username} authentication failed")
        return paramiko.AUTH_FAILED

    def check_auth_publickey(self, username, key):
        if not self.allowPkey:
            logger.warning('Attempted Public Key auth, but is not allowed')
            return paramiko.AUTH_FAILED
        logger.debug(f"User {username} tries to authenticate with key {u(hexlify(key.get_fingerprint()))}")
        for user in self.allowedUsers:
            if ((user['username'] == '') or (user['username'] == username)) and (user['pkey'] == key):
                logger.debug(f"User {username} authenticated successfully")
                return paramiko.AUTH_SUCCESSFUL
        logger.warning(f"User {username} authentication failed")
        return paramiko.AUTH_FAILED

    def get_allowed_auths(self, username):
        result=[]
        if not not self.allowPkey:
            result.append('publickey')
        if not not self.allowPass:
            result.append('password')
        return ','.join(result)

    def check_channel_shell_request(self, channel):
        if not self.allowSession:
            return False
        self.event.set()
        self.chanInfo={
            'type': 'session'
        }
        return True

    def check_channel_pty_request(
        self, channel, term, width, height, pixelwidth, pixelheight, modes
    ):
        if not self.allowSession:
            return False
        return True
    
    def check_channel_direct_tcpip_request(self, 
                                           chanid, 
                                           origin, 
                                           destination):
        if not self.allowDirectTcpip:
            return False
        logger.info(f"Direct Tcp-IP request from {origin} to {destination}")
        self.event.set()
        self.chanInfo={
            'type': 'directTcpip',
            'chanid': chanid,
            'origin': origin,
            'destination': destination
        }
        return paramiko.OPEN_SUCCEEDED

