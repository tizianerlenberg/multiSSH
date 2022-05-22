#!/usr/bin/env python3

import threading
import socket
import queue
import logging
import sys

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

formatter = logging.Formatter('[%(name)s] %(message)s')

if __name__ != '__main__':
    file_handler = logging.FileHandler(f"{sys.argv[0][2:-3]}_imported_{__name__}.log")
else:
    file_handler = logging.FileHandler(f"{sys.argv[0][2:-3]}.log")
file_handler.setFormatter(formatter)
file_handler.setLevel(logging.INFO)

stream_handler = logging.StreamHandler()
stream_handler.setFormatter(formatter)
stream_handler.setLevel(logging.DEBUG)

#logger.addHandler(file_handler)
logger.addHandler(stream_handler)

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

def forward(source, destination):
    threadName=threading.current_thread().name
    try:
        string = ' '
        while string:
            string = source.recv(1024)
            if string:
                destination.sendall(string)
    except:
        logger.exception(f"ERROR IN FORWARD ({threadName})")
    finally:
        logger.info(f"{threadName}: source was {source.getpeername()}")
        logger.info(f"{threadName}: destination was {destination.getpeername()}")
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
    logger.info(f"combinedForward: closing socket: {source.getpeername()}")
    source.close()
    logger.info(f"combinedForward: closing socket: {destination.getpeername()}")
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
