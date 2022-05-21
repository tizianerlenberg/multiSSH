#!/usr/bin/env python3

import threading
import socket
import time
import atexit

SERVER= ("127.0.0.1", 2233)
#SERVER = ("192.52.45.151", 2233)
LOCAL_SSH = ("127.0.0.1", 22)
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
    print("Sent my go")
    threading.Thread(target=forward, args=(REMOTE_SOCK, LOCAL_SOCK,)).start()
    threading.Thread(target=forward, args=(LOCAL_SOCK, REMOTE_SOCK,)).start()


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

def main():
    startOfProgram()

if __name__ == '__main__':
    main()
