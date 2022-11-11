import safeSocket2, subprocess

s=safeSocket2.SafeSocket()
s.bind(("127.0.0.1",4445))
s.listen(5)


while(True):
    conn = s.accept()[0]
    print("[CLIENT CONNECTED]")

    while(True):
        answer=conn.recv(1024)
        if(answer==b""):
            print("[CLIENT DISCONNECTED]")
            break
        result = subprocess.run(answer.decode(), capture_output=True, shell=True)
        if(result.stdout == b""):
            conn.sendall(b"MYNULL")
        else:
            conn.sendall(result.stdout)

