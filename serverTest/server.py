import socket, threading, time

# own libraries
import logHandler

logger = logHandler.getSimpleLogger(__name__, streamLogLevel=logHandler.DEBUG)

def serve(sock, name='unknown'):
    try:
        while True:
            answer = sock.recv(1024)
            if answer == b'':
                raise
            logger.info(f"[{name}] {answer.decode()}")
    finally:
        logger.info(f"Client {name} disconnected, trying to close socket")
        try:
            sock.close
            logger.info(f"Socket for client {name} closed")
        except:
            logger.error(f"Could not close socket for client {name}")
        return

def listener(sock):
    try:
        while(True):
            logger.debug(f"Waiting for connection")
            conn, addr = sock.accept()
            logger.info(f"Client {addr} connected")
            threading.Thread(target=serve, args=(conn,addr,)).start()
    except:
        logger.exception(f"Exception occurred: ")
    finally:
        logger.info(f"Trying to close socket {addr}")
        try:
            conn.close()
            logger.info(f"Socket for client {addr} closed")
        except:
            logger.error(f"Could not close socket for client {addr}")
        return

def start_server(host):
    sock=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    #sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    logger.debug(f"Binding socket")
    sock.bind(host)
    sock.listen(10)
    
    threading.Thread(target=listener, args=(sock,)).start()

    return sock

def main():
    logger.debug(f"Starting server")
    sock = start_server(("127.0.0.1",4445))
    
    try:
        while True:
            print("Active threads: ", threading.active_count())
            time.sleep(2)
            pass
    finally:
        sock.close()

if __name__ == '__main__':
    main()
