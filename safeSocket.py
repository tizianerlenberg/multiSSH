import socket
import queue
import threading
import enum

# own libraries
import logHandler

logger = logHandler.getSimpleLogger(__name__, streamLogLevel=logHandler.DEBUG, fileLogLevel=logHandler.DEBUG)

class Type(enum.Enum):
    SERVER = "SERVER"
    CLIENT = "CLIENT"
    SERVER_CONNECTED = "SERVER_CONNECTED"
    CLIENT_CONNECTED = "CLIENT_CONNECTED"
    DEFAULT = "DEFAULT"

class SafeSocket():
    def __init__(self, sock=socket.socket(socket.AF_INET, socket.SOCK_STREAM), type=Type.DEFAULT):
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.settimeout(10)
        self._addr = None
        self._closed = True
        self._timeout = 600
        self._listenQueue = None
        self._sendQueue = None
        self._recvQueue = None
        self._childs = None

        self._listener_thread = None
        self._sender_thread = None
        self._recver_thread = None

        if type == Type.SERVER:
            pass
        elif type == Type.CLIENT:
            pass
        elif type == Type.SERVER_CONNECTED:
            self._sock = sock
        elif type == Type.CLIENT_CONNECTED:
            self._sock = sock
        else:
            pass
    def _sender(self):
        try:
            while True:
                try:
                    self._sock.sendall(self._sendQueue.get(timeout=5))
                except queue.Empty:
                    if self._closed == True:
                        raise
                    self._sock.sendall("alv")
        finally:
            self.close()
    def _recver(self):
        try:
            alvCounter = 0
            while True:
                msg=""
                try:
                    msg = self._sock.recv(3)
                    if msg == "cst":
                        length = self._sock.recv(6)
                        msg = self._sock.recv(length)
                        self._recvQueue.put(msg)
                    elif msg == "alv":
                        alvCounter += 1
                except TimeoutError:
                    if self._closed == True:
                        raise
                    if alvCounter > 0:
                        alvCounter = 0
                    else:
                        raise
        finally:
            self.close()
    def _listener(self):
        try:
            sock = self._sock.accept()
            self._listenQueue.put(SafeSocket(sock))
        except TimeoutError:
            if self._closed == True:
                raise
    def bind(self, addr):
        self._addr = addr
        self._sock.bind(addr)
        self._closed = False
        return self._sock
    def connect(self, addr):
        self._addr = addr
        sock = self._sock.connect(addr)
        self._closed = False
        return sock
    def listen(self):
        self._listenQueue = queue.Queue()
        self._sock.listen()
        self._listener_thread = threading.Thread(target=self._listener)
        self._listener_thread.start()
    def accept(self):
        if self._listenQueue == None:
            raise Exception()
        return self._listenQueue.get(timeout=self._timeout)
    def send(self, toSend):
        self._sendQueue.put(toSend)
    def sendall(self, toSend):
        self._sendQueue.put(toSend)
    def recv(self, n=None):
        if n==None:
            return self._recvQueue.get()
    def settimeout(self, n):
        self._timeout = n
    def close(self):
        self._sock.close()
        self._closed = True

def main():
    sock = SafeSocket()

if __name__ == '__main__':
    main()
