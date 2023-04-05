#!/usr/bin/env python3

import erlenberg.logHandler
logger = erlenberg.logHandler.Logger(erlenberg.logHandler.DEBUG, pp=True).start()

import queue
import io

class FakeSocket():
    def __init__(self):
        self.stream = b''
        self.partner = None
        self.timeout = 0
    def close(self):
        self.sendall(b'')
    def settimeout(self, timeout):
        self.timeout = timeout
    def send(self, content):
        self.sendall(content)
    def sendall(self, content):
        self.partner.internalSend(content)
    def recv(self, amount):
        return self.internalRecv(amount)
    def internalSend(self, content):
        self.stream = self.stream + content
    def internalRecv(self, amount):
        toReturn = self.stream[:amount]
        self.stream = self.stream[amount:]
        return toReturn
    def setPartner(self, sock):
        self.partner = sock

def getFakeSocketPair():
    sock1 = FakeSocket()
    sock2 = FakeSocket()
    sock1.setPartner(sock2)
    sock2.setPartner(sock1)
    return sock1, sock2

def startOfProgram():
    sock1, sock2 = getFakeSocketPair()
    sock1.send(b'hallo welt')
    print(f"sock1: {sock1.stream}")
    print(f"sock2: {sock2.stream}")
    print(sock2.recv(4))
    print(sock2.recv(4))
    print(sock2.recv(4))

def main():
    startOfProgram()

if __name__ == '__main__':
    main()
