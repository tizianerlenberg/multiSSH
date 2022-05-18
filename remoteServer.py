#!/usr/bin/env python3

import threading
import socket
import time
import queue

LOCAL = ("0.0.0.0", 2233)
LOCAL_SOCK = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
HOSTS = {}
CLIENTS = queue.Queue()
EROOR = ""

def startOfProgram():
    global LOCAL_SOCK
    global ERROR

    server()
    while True:
        if ERROR != "":
            #LOCAL_SOCK.close()
            print("Error: ", ERROR)
            ERROR = ""
            #server()

def server():
    global LOCAL
    global LOCAL_SOCK
    global HOSTS

    LOCAL_SOCK = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    LOCAL_SOCK.bind(LOCAL)

    threading.Thread(target=listener).start();

    while True:
        print(HOSTS)
        time.sleep(1)

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
        print(e)
        source.close()
        destination.close()
        ERROR = e

def listener():
    global LOCAL_SOCK
    global HOSTS
    global CLIENTS
    while True:
        LOCAL_SOCK.listen()
        sock = LOCAL_SOCK.accept()[0]
        print("hi")
        msg = sock.recv(1024).decode()
        print(msg)
        if msg.startswith("offer"):
            HOSTS[msg[7:]] = sock
        elif msg.startswith("query"):
            sock.sendall(("\n".join(HOSTS.keys())).encode())
            threading.Thread(target=handleRequests, args=(sock,)).start()

def handleRequests(sock):
    global HOSTS
    request = sock.recv(1024).decode()
    request = request[9:]
    print(request)
    hostSock = HOSTS[request]

    hostSock.sendall(b"request")
    response = hostSock.recv(1024).decode()
    if response == "go":
        sock.sendall(b"go")
        threading.Thread(target=forward, args=(hostSock, sock,)).start()
        threading.Thread(target=forward, args=(sock, hostSock,)).start()
        while True:
            pass


def main():
    server()

if __name__ == '__main__':
    main()
