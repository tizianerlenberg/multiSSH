#!/usr/bin/env python3

import threading
import socket

SERVER= ("127.0.0.1", 2233)
LOCAL_SSH = ("127.0.0.1", 22)
REMOTE_SOCK = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
LOCAL_SOCK = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
ERROR = ""

def startOfProgram():
    global REMOTE_SOCK
    global LOCAL_SOCK
    global ERROR

    server()
    while True:
        if ERROR != "":
            REMOTE_SOCK.close()
            LOCAL_SOCK.close()
            print("Error: ", ERROR)
            ERROR = ""
            server()

def server():
    global SERVER
    global LOCAL_SSH
    global REMOTE_SOCK
    global LOCAL_SOCK

    REMOTE_SOCK = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    REMOTE_SOCK.connect(SERVER)

    while True:
        REMOTE_SOCK.sendall(("offer: " + socket.gethostname()).encode())
        serverResponse = REMOTE_SOCK.recv(1024).decode()
        if serverResponse == "request":
            break

    LOCAL_SOCK = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    LOCAL_SOCK.connect(LOCAL_SSH)

    REMOTE_SOCK.sendall(b"go")
    threading.Thread(target=forward, args=(REMOTE_SOCK, LOCAL_SOCK,)).start()
    threading.Thread(target=forward, args=(LOCAL_SOCK, REMOTE_SOCK,)).start()


def forward(source, destination):
    global ERROR
    try:
        string = ' '
        while string:
            string = source.recv(1024)
            if string:
                destination.sendall(string)
            else:
                source.shutdown(socket.SHUT_RD)
                destination.shutdown(socket.SHUT_WR)
    except Exception as e:
        ERROR = e

def main():
    startOfProgram()

if __name__ == '__main__':
    main()
