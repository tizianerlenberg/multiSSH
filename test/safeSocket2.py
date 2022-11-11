import socket
import queue
import threading
import enum

# own libraries
import logHandler

logger = logHandler.getSimpleLogger(__name__, streamLogLevel=logHandler.DEBUG, fileLogLevel=logHandler.DEBUG)

class MsgType():
    ACK = bytes.fromhex(' 00 ')
    ALV = bytes.fromhex(' 01 ')
    BYT = bytes.fromhex(' 02 ')
    M01 = bytes.fromhex(' 03 ')
    M05 = bytes.fromhex(' 04 ')
    M10 = bytes.fromhex(' 05 ')

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

class SafeSocket():
    def __init__(self, sock=socket.socket(socket.AF_INET, socket.SOCK_STREAM)):
        logger.debug(f"SafeSocket initialisation started")
        self.sock=sock
        logger.debug(f"SafeSocket initialized")
    def bind(self, host):
        self.sock.bind(host)
    def listen(self, numberOfHosts=0):
        self.sock.listen(numberOfHosts)
    def accept(self):
        pair=self.sock.accept()
        return (SafeSocket(pair[0]), pair[1])
    def connect(self, host):
        self.sock.connect(host)
    def sendall(self, msg):
        msgLength = str(len(msg))
        self.sock.sendall(b'nmsg' + (msgLength.rjust(20, '0')).encode() + msg)
    def recv(self, bufsize):
        msgType = self.sock.recv(4)
        if(msgType == b"nmsg"):
            msgLength = int((self.sock.recv(20)).decode())
            msg = self.sock.recv(msgLength)
            return msg
        else:
            print("unknown type: " + msgType.decode())
    def close(self):
        self.sock.close();
    def shutdown(self, type):
        try:
            logger.debug(f"trying to shutdown source: {getSockName(self.sock)}")
            self.sock.shutdown(type)
        except:
            logger.debug(f"shutdown failed on source: {getSockName(self.sock)}, closing socket ")
            self.sock.close()

def main():
    sock = SafeSocket()

if __name__ == '__main__':
    main()
