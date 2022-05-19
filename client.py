#!/usr/bin/env python3

import threading
import socket
import json
import time
import atexit

SERVER = ("127.0.0.1", 2233)
LOCAL_SSH = ("127.0.0.1", 2222)
REMOTE_SOCK = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
LOCAL_SOCK = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
ERROR = "start"
#ERROR_QUEUE = []

def exit_handler():
    REMOTE_SOCK.close()
    LOCAL_SOCK.close()

def startOfProgram():
    global REMOTE_SOCK
    global LOCAL_SOCK
    global ERROR

    atexit.register(exit_handler)

    while True:
        if ERROR != "":
            REMOTE_SOCK.close()
            LOCAL_SOCK.close()
            ERROR = ""
            try:
                server()
            except Exception as e:
                ERROR = e
                print("Error in Thread MAIN: ", e)
        print("Active Threads: ", threading.active_count())
        time.sleep(1)

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
    else:
        print("ERROR")

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
        print(f"Error in Thread {threading.get_ident()}: {e}")
        time.sleep(5)
        ERROR = e

def main():
    startOfProgram()

if __name__ == '__main__':
    main()
