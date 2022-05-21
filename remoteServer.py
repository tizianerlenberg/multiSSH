#!/usr/bin/env python3

import threading
import socket
import time
import queue
import atexit

LOCAL = ("0.0.0.0", 2233)
LOCAL_SOCK = ""
HOSTS = {}
CLIENTS = queue.Queue()
ERROR = "start"

def exit_handler():
    for value in HOSTS.values():
        value.close()
    if LOCAL_SOCK != "":
        LOCAL_SOCK.close()

def startOfProgram():
    global LOCAL_SOCK
    global ERROR

    atexit.register(exit_handler)

    while True:
        if ERROR != "":
            ERROR = ""
            try:
                server()
            except Exception as e:
                ERROR = e
                print("Error in Thread MAIN: ", e)
        print("Active Threads: ", threading.active_count())
        print(HOSTS)
        time.sleep(1)

def server():
    global LOCAL
    global LOCAL_SOCK
    global HOSTS

    if LOCAL_SOCK == "":
        LOCAL_SOCK = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        LOCAL_SOCK.bind(LOCAL)

    threading.Thread(target=listener).start();

def forward(source, destination):
    global ERROR
    myError = "LIGHT ERROR"
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
        myError = e
    finally:
        print(f"Error in Thread {threading.get_ident()}: {myError}")
        ERROR = myError

def listener():
    global LOCAL_SOCK
    global HOSTS
    global CLIENTS
    myError = "LIGHT ERROR"
    try:
        while True:
            LOCAL_SOCK.listen()
            sock = LOCAL_SOCK.accept()[0]
            print("hi")
            msg = sock.recv(1024).decode()
            print(msg)
            if msg.startswith("offer"):
                if (msg[7:] in HOSTS):
                    HOSTS[msg[7:]].close()
                HOSTS[msg[7:]] = sock
            elif msg.startswith("query"):
                sock.sendall(("\n".join(HOSTS.keys())).encode())
                threading.Thread(target=handleRequests, args=(sock,)).start()
    except Exception as e:
        myError = e
    finally:
        print(f"Error in Thread {threading.get_ident()}: {myError}")
        ERROR = myError
        sock.close()
        threading.Thread(target=listener).start();


def handleRequests(sock):
    global HOSTS
    request = sock.recv(1024).decode()
    request = request[9:]
    print(request)
    hostSock = HOSTS[request]

    hostSock.sendall(b"request")
    response = hostSock.recv(1024).decode()
    if response == "go":
        print("RECEIVED GO")
        sock.sendall(b"go")
        print("SENT MY GO")
        threading.Thread(target=forward, args=(hostSock, sock,)).start()
        threading.Thread(target=forward, args=(sock, hostSock,)).start()


def main():
    startOfProgram()

if __name__ == '__main__':
    main()
