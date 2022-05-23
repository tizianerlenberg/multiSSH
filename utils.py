#!/usr/bin/env python3

import threading
import socket
import queue
import logging
import logHandler

logger = logging.getLogger(__name__)
# don't change log level here! change it in logHandler.py instead
logger.setLevel(logging.DEBUG)

logger.addHandler(logHandler.stream_handler)
logger.addHandler(logHandler.file_handler)

#-------------------------------------------------------------------------------

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

def getSockName(sock):
    try:
        peer=sock.getpeername()
    except:
        return f"{sock.getsockname()}"
    else:
        return f"[{sock.getsockname()} connected to {peer}]"

def forward(source, destination):
    threadName=threading.current_thread().name
    try:
        string = ' '
        while string:
            string = source.recv(1024)
            if string:
                destination.sendall(string)
    except:
        logger.exception(f"Error in ({threadName})")
        logger.info(f"{threadName}: source was {source.getpeername()}")
        logger.info(f"{threadName}: destination was {destination.getpeername()}")
    finally:
        logger.info(f"closing forward ({threadName})")
        source.shutdown(socket.SHUT_RD)
        destination.shutdown(socket.SHUT_WR)

def combinedForward(source, destination, done=LockedVar()):
    t1= threading.Thread(target=forward, args=(source, destination,))
    t2= threading.Thread(target=forward, args=(destination, source,))
    t1.start()
    t2.start()
    t1.join()
    t2.join()
    logger.info(f"combinedForward: closing socket: {getSockName(sock)}")
    source.close()
    logger.info(f"combinedForward: closing socket: {getSockName(destination)}")
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

def listener(sock, connectionQueue, stop=None, done=LockedVar()):
    try:
        while True:
            conn= sock.accept()
            msg= conn[0].recv(1024).decode()
            connectionQueue.put([conn, msg])
    except:
        logger.exception("ERROR IN LISTENER")
    finally:
        done.set(True)
