#!/usr/bin/env python3

import threading
import socket
import queue
import platform

#own libraries
import logHandler

logger = logHandler.getSimpleLogger(__name__, streamLogLevel=logHandler.DEBUG, fileLogLevel=logHandler.DEBUG)

# ------------------------------------------------------------------------------

class Locked(Exception):
    pass

class LockedVar():
    def __init__(self, initVal=None):
        self.var=initVal
        self.lock=threading.Lock()
    def get(self):
        return self.var
    def set(self, val):
        self.lock.acquire()
        self.var=val
        self.lock.release()
    def set_nowait(self, val):
        if self.lock.acquire(False):
            self.var=val
            self.lock.release()
        else:
            raise Locked("Variable is locked")

class LockedDict():
    def __init__(self, initVal={}):
        self.dict=initVal
        self.lock=threading.Lock()
    def get(self, key):
        return self.dict[key]
    def put(self, key, val):
        self.lock.acquire()
        self.dict[key]=val
        self.lock.release()
    def put_nowait(self, key, val):
        if self.lock.acquire(False):
            self.dict[key]=val
            self.lock.release()
        else:
            raise Locked("Variable is locked")
    def pop(self, key):
        pass

if platform.system() == "Windows":
    import msvcrt
    def getch():
        return msvcrt.getch()
    def getche():
        return msvcrt.getche()
else:
    import getch
    def getch():
        return getch.getch()
    def getche():
        return getch.getche()

def getSockName(sock):
    try:
        try:
            peer=sock.getpeername()
        except:
            return f"{sock.getsockname()}"
        else:
            return f"[{sock.getsockname()} connected to {peer}]"
    except:
        return "[some socket (closed)]"

def forward(source, destination):
    try:
        string = ' '
        while string:
            string = source.recv(1024)
            if string:
                destination.sendall(string)
    except:
        logger.warning(f"exception in forward")
        logger.exception("")
        logger.debug(f"source was {getSockName(source)}")
        logger.debug(f"destination was {getSockName(destination)}")
    finally:
        logger.info(f"received disconnect, closing forward")
        try:
            logger.debug(f"trying to shutdown source: {getSockName(source)}")
            source.shutdown(socket.SHUT_RD)
        except:
            logger.debug(f"shutdown failed on source: {getSockName(source)}, closing socket ")
            source.close()
        try:
            logger.debug(f"trying to shutdown destination: {getSockName(destination)}")
            destination.shutdown(socket.SHUT_WR)
        except:
            logger.debug(f"shutdown failed on destination: {getSockName(destination)}, closing socket ")
            destination.close()

def combinedForward(source, destination, done=LockedVar()):
    t1= threading.Thread(target=forward, args=(source, destination,))
    t2= threading.Thread(target=forward, args=(destination, source,))
    t1.start()
    t2.start()
    t1.join()
    t2.join()
    logger.debug(f"closing socket: {getSockName(source)}")
    source.close()
    logger.debug(f"closing socket: {getSockName(destination)}")
    destination.close()
    done.set(True)

def selectFrom(myList):
    outList = []
    for index, value in enumerate(myList):
        outList.append(str(index+1) + " / " + value)
    print("\n".join(outList))
    print()
    myChoice = int(input("Please choose a number: "))
    return  myList[myChoice-1]

def listener(sock, connectionQueue, done=LockedVar()):
    try:
        while True:
            conn= sock.accept()
            msg= conn[0].recv(1024).decode()
            connectionQueue.put([conn, msg])
    except:
        logger.exception("error")
    finally:
        done.set(True)
