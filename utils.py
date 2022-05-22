#!/usr/bin/env python3

import threading
import queue
import logging

logger = logging.getLogger(__name__)
logger.setLevel(logging.CRITICAL)

formatter = logging.Formatter('[%(name)s] %(message)s')

#file_handler = logging.FileHandler('sample.log')
#file_handler.setLevel(logging.ERROR)
#file_handler.setFormatter(formatter)

stream_handler = logging.StreamHandler()
stream_handler.setFormatter(formatter)

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
        self.lock.aquire()
        self.var=val
        self.lock.release()
    def set_nowait(self, val):
        if self.lock.aquire(False):
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
        self.lock.aquire()
        self.dict[key]=val
        self.lock.release()
    def put_nowait(self, key, val):
        if self.lock.aquire(False):
            self.dict[key]=val
            self.lock.release()
        else:
            raise Locked("Variable is locked")
    def pop(self, key):
        pass

def forward(source, destination, errorQueue=None):
    try:
        string = ' '
        while string:
            string = source.recv(1024)
            if string:
                destination.sendall(string)
    except Exception as e:
        if errorQueue:
            errorQueue.put([threading.current_thread().name, e])
        else:
            print(f"Error in {threading.current_thread().name}: {e}")
    finally:
        source.shutdown(socket.SHUT_RD)
        destination.shutdown(socket.SHUT_WR)

def combinedForward(source, destination, done=LockedVar(), errorQueue=None):
    t1= threading.Thread(target=forward, args=(source, destination, errorQueue,))
    t2= threading.Thread(target=forward, args=(destination, source, errorQueue,))
    t1.start()
    t2.start()
    t1.join()
    t2.join()
    done.set(True)

def selectFrom(myList):
    outList = []
    for index, value in enumerate(myList):
        outList.append(str(index+1) + " / " + value)
    print("\n".join(outList))
    print()
    myChoice = int(input("Please choose a number: "))
    return  myList[myChoice-1]

def listener(sock, connectionQueue, stop=None, done=LockedVar(), errorQueue=None):
    try:
        while True:
            conn= sock.accept()
            msg= conn[0].recv(1024).decode()
            connectionQueue.put([conn, msg])
    except Exception as e:
        if errorQueue:
            errorQueue.put([threading.current_thread().name, e])
        else:
            print(f"Error in {threading.current_thread().name}: {e}")
    finally:
        done.set(True)

def errorListner(errorQueue):
    while True:
        newError=errorQueue.get()
        if newError == "END":
            break
        print(f"[ERROR] {newError[0]}: {newError[1]}")


import traceback

try:
    raise Exception("hallo")
except:
    logger.exception("my text")

print("hi")
