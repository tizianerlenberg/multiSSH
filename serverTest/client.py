import socket, threading, time

# own libraries
import logHandler

logger = logHandler.getSimpleLogger(__name__, streamLogLevel=logHandler.DEBUG)

def communicator(sock, name='unknown'):
    try:
        logger.debug(f"Trying to connect to server {name}")
        sock.connect(name)
        logger.info(f"CONNECTED TO SERVER: {name}")
        while True:
            logger.info(f"Sending ping to {name}")
            sock.sendall(b'ping')
            time.sleep(5)
    finally:
        logger.exception('')
        logger.info(f"Server {name} disconnected, trying to close socket")
        try:
            sock.close
            logger.info(f"Socket for server {name} closed")
        except:
            logger.error(f"Could not close socket for server {name}")
        return

def start_client(host):
    sock=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    #sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    threading.Thread(target=communicator, args=(sock, host,)).start()
    return sock

def client(host):
    s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    #s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.connect(host)
    print("[CONNECTED TO SERVER]")
    while True:
        s.sendall(input(">>>").encode())

def main():
    #client(("127.0.0.1",4445))
    logger.debug(f"Starting server")
    sock = start_client(("127.0.0.1",4445))

    try:
        while True:
            pass
    finally:
        sock.close()

if __name__ == '__main__':
    main()
