#!/usr/bin/env python3

import threading
import socket

def server():
    try:
        dock_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        dock_socket.bind(('0.0.0.0', 2222))
        dock_socket.listen(5)
        while True:
            client_socket = dock_socket.accept()[0]
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_socket.connect(("192.52.45.151", 2233))
            threading.Thread(target=forward, args=(client_socket, server_socket,)).start();
            threading.Thread(target=forward, args=(server_socket, client_socket,)).start();
    finally:
        threading.Thread(target=server);

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
