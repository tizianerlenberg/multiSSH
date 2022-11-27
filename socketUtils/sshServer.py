import socket
import sshServerSocket
import utils

s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1",4445))
s.listen(5)

try:
    sock = s.accept()[0]
    print("[CLIENT CONNECTED]")
    sshSock = sshServerSocket.SshServerSocket(sock, password="hallo")
    sshSock.start()
    conn = sshSock.chan
    #conn.send(b"\r\n\r\nWelcome !\r\n\r\n")
    #while(True):
    #    print(conn.recv(1024))

    s2=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s2.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s2.connect(("192.52.43.156",22))
    utils.combinedForward(conn, s2)
    
finally:
    sshSock.close()
    sock.close()
    s.close()
