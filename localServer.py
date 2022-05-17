#!/usr/bin/env python3

import threading
import socket

def server():
    remote_server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    remote_server_socket.connect(("192.52.45.151", 2233))

    while True:
        try:
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_socket.connect(("127.0.0.1", 22))

            threading.Thread(target=forward, args=(remote_server_socket, server_socket,)).start();
            threading.Thread(target=forward, args=(server_socket, remote_server_socket,)).start();
            while True:
                pass
        except:
            pass


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
