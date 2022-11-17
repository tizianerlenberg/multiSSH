import socket
import sshClientSocket

s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.connect(("127.0.0.1",4445))
print("[CONNECTED TO SERVER]")

try:
    sshSock = sshClientSocket.SshClientSocket(s)
    conn = sshSock.start_client()
    print(conn.recv(1024).decode())
finally:
    conn.close()
    s.close()