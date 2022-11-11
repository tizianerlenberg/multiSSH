import socket
import queue
import threading
import enum

# own libraries
import logHandler

logger = logHandler.getSimpleLogger(__name__, streamLogLevel=logHandler.DEBUG, fileLogLevel=logHandler.DEBUG)

class MsgType():
    Acknowledge  = b'\x00'
    Alive        = b'\x01'
    Byte         = b'\x02'
    Message_01   = b'\x03'
    Message_05   = b'\x04'
    Message_10   = b'\x05'

def encodeString(msg):
    msgLength = len(msg)
    if(msgLength <= 255):
        return MsgType.Message_01 + msgLength.to_bytes(1, 'big') + msg
    elif(msgLength <= 1099511627775):
        return MsgType.Message_05 + msgLength.to_bytes(5, 'big') + msg
    elif(msgLength <= 1208925819614629174706175):
        return MsgType.Message_10 + msgLength.to_bytes(10, 'big') + msg
    else:
        print('error')

def recvMsg(sock):
    msgType = sock.recv(1)
    match msgType:
        case MsgType.Acknowledge:
            return 'Acknowledge'
        case MsgType.Alive:
            return 'Alive'
        case MsgType.Byte:
            return sock.recv(1)
        case MsgType.Message_01:
            codedLength = sock.recv(1)
            msgLength = int.from_bytes(codedLength, 'big')
            return sock.recv(msgLength)
        case MsgType.Message_05:
            codedLength = sock.recv(5)
            msgLength = int.from_bytes(codedLength, 'big')
            return sock.recv(msgLength)
        case MsgType.Message_10:
            codedLength = sock.recv(10)
            msgLength = int.from_bytes(codedLength, 'big')
            return sock.recv(msgLength)

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
        self.sock.sendall(encodeString(msg))
    def recv(self, bufsize):
        return self.sock.recv(bufsize)
    def recvall(self):
        return recvMsg(self.sock)
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
