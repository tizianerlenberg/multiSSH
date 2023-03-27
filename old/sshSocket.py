import paramiko.channel

# own libraries
import logHandler

logger = logHandler.getSimpleLogger(__name__, streamLogLevel=logHandler.DEBUG, fileLogLevel=logHandler.DEBUG)

class SshSocket():
    def __init__(self, sock, hostname='tunnel', username='tunnel', host_key=example_public_server_key, client_key=example_private_client_key, password=None):
        pass

def main():
    pass

if __name__ == '__main__':
    main()
