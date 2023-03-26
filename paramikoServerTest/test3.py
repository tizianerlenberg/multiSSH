import paramiko
import socket
import threading

#host = "192.52.45.151"
host = "127.0.0.1"
port = 2201
username = "debian"

def test1():
    global host
    global username
    client = paramiko.client.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(host, username=username)
    _stdin, _stdout,_stderr = client.exec_command("ls")
    print(_stdout.read().decode())
    client.close()

def test2():
    global host
    global username
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((host,22))
    t = paramiko.Transport(sock)
    t.connect(username=username)
    t.send("ls")
    print(t.recv())

def thread_function(chan):
    print("IM HERE")
    while(True):
        chan.send(input(">>> ").encode() + b'\r\n')

def test3():
    global host
    global username
    client = paramiko.client.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(host, username=username)
    chan = client.invoke_shell()
    x = threading.Thread(target=thread_function, args=(chan,))
    x.start()
    while(True):
        print(chan.recv(1024))
    
    chan.close()
    client.close()

def test4():
    global host
    global port
    global username
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((host,port))
    #t = paramiko.Transport(sock)
    #t.connect(username=username)
    client = paramiko.client.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(host, username="robey", sock=sock)
    t = client.get_transport()

    chan = t.open_session()
    term='vt100'
    width=80
    height=24
    width_pixels=0
    height_pixels=0

    chan.get_pty(term, width, height, width_pixels, height_pixels)
    chan.invoke_shell()

    x = threading.Thread(target=thread_function, args=(chan,))
    x.start()
    while(True):
        res = chan.recv(1024)
        print(res)
        if res == b'':
            break
    
    chan.close()
    client.close()

    


test4()