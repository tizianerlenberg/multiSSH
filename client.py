#!/usr/bin/env python3

import threading
import socket
import json

SERVER = ("127.0.0.1", 2233)
LOCAL_SSH = ("127.0.0.1", 2222)
REMOTE_SOCK = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
LOCAL_SOCK = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

def startOfProgram():
    while True:
        try:
            server()
        except Exception as e:
            #TODO: Close sockets
            print("Error: ", e)

def selectFrom(myList):
    outList = []
    for index, value in enumerate(myList):
        outList.append(str(index+1) + " / " + value)
    print("\n".join(outList))
    print()
    myChoice = int(input("Please choose a number: "))
    return  myList[myChoice-1]

def server():
    global SERVER
    global REMOTE_SOCK
    global LOCAL_SSH
    global LOCAL_SOCK

    REMOTE_SOCK = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    REMOTE_SOCK.connect(SERVER)
    REMOTE_SOCK.sendall(b"query")
    availableHosts = REMOTE_SOCK.recv(1024).decode()
    availableHosts = availableHosts.split("\n")
    myChoice = selectFrom(availableHosts)
    print(myChoice)

    REMOTE_SOCK.sendall(("request: " + myChoice).encode())

    ack = REMOTE_SOCK.recv(1024).decode()
    if ack == "go":
        LOCAL_SOCK = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        LOCAL_SOCK.bind(LOCAL_SSH)
        LOCAL_SOCK.listen(1)
        sock = LOCAL_SOCK.accept()[0]
        threading.Thread(target=forward, args=(sock, REMOTE_SOCK,)).start();
        threading.Thread(target=forward, args=(REMOTE_SOCK, sock,)).start();
        while True:
            pass
    else:
        print("ERROR")

def forward(source, destination):
    string = ' '
    while string:
        string = source.recv(1024)
        if string:
            destination.sendall(string)
        else:
            source.shutdown(socket.SHUT_RD)
            destination.shutdown(socket.SHUT_WR)

def main():
    server()

if __name__ == '__main__':
    main()
