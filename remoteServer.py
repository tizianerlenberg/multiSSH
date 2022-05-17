#!/usr/bin/env python3

import threading
import socket

def server():
    dock_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    dock_socket.bind(('0.0.0.0', 2233))
    dock_socket.listen(5)
    client_socket = dock_socket.accept()[0]
    while True:
        try:
            dock_socket.listen(5)
            local_server_socket = dock_socket.accept()[0]

            threading.Thread(target=forward, args=(client_socket, local_server_socket,)).start();
            threading.Thread(target=forward, args=(local_server_socket, client_socket,)).start();
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
