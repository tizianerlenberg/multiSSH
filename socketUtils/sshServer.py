import socket
import sshServerSocket

s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1",4445))
s.listen(5)

try:
    sock = s.accept()[0]
    print("[CLIENT CONNECTED]")
    sshSock = sshServerSocket.SshServerSocket(sock)
    conn = sshSock.start_server()
    conn.send(b"\r\n\r\nWelcome !\r\n\r\n")
finally:
    sshSock.close()
    sock.close()
    s.close()

