import safeSocket2, subprocess

s=safeSocket2.SafeSocket()
s.connect(("127.0.0.1",4445))


while(True):
    s.sendall(input(">>> ").encode())
    print(s.recv(1024).decode())
