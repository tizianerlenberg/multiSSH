import socket, threading, traceback

# own libraries
import logHandler

logger = logHandler.getSimpleLogger(__name__, streamLogLevel=logHandler.DEBUG)

class Server():
    def __init__(self, address, serve=None):
        self.address = address
        self.serve=serve
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.hosts = []
        
    def serveWrapper(self, host):
        try:
            if not (self.serve == None):
                self.serve(host)
        except:
            logger.warn(f"Exception in serve() method of client {host[1]}:")
            #traceback.print_exc()
        logger.info(f"Trying to close socket for client {host[1]}")
        try:
            host[0].close
            logger.info(f"Socket for client {host[1]} closed")
        except:
            logger.warn(f"Could not close socket for client {host[1]}")
        self.hosts.remove(host)
    def listener(self):
        try:
            while(True):
                logger.debug(f"Waiting for connection")
                host = self.sock.accept()
                logger.info(f"Client {host[1]} connected")
                self.hosts.append(host)
                threading.Thread(target=self.serveWrapper, daemon=True, args=(host,)).start()
        finally:
            logger.info(f"Trying to close socket {host[1]}")
            try:
                conn.close()
                logger.info(f"Socket for client {host[1]} closed")
            except:
                logger.warn(f"Could not close socket for client {host[1]}")
    def start(self):
        logger.debug(f"Binding socket")
        self.sock.bind(self.address)
        self.sock.listen(10)

        logger.debug(f"Starting listener")
        threading.Thread(target=self.listener, daemon=True).start()
    def stop(self):
        for host in self.hosts:
            try:
                logger.debug(f'Trying to close socket for client {host[1]}')
                host[0].close()
                logger.debug(f'Closed socket for client {host[1]}')
            except:
                logger.error(f'Closing socket for client {host[1]} failed')
        try:
            logger.debug(f'Trying to close server socket')
            self.sock.close()
            logger.debug(f'Closed server socket')
        except:
            logger.error(f'Failed to close server socket')


