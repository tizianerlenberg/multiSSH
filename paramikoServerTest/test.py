#!/usr/bin/env python

# Copyright (C) 2003-2007  Robey Pointer <robeypointer@gmail.com>
#
# This file is part of paramiko.
#
# Paramiko is free software; you can redistribute it and/or modify it under the
# terms of the GNU Lesser General Public License as published by the Free
# Software Foundation; either version 2.1 of the License, or (at your option)
# any later version.
#
# Paramiko is distributed in the hope that it will be useful, but WITHOUT ANY
# WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
# A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more
# details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with Paramiko; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301 USA.

import base64
from binascii import hexlify
import os
import socket
import sys
import threading
import traceback

import paramiko
from paramiko.py3compat import b, u, decodebytes


# setup logging
paramiko.util.log_to_file("demo_server.log")

host_key = paramiko.RSAKey(filename="test_rsa.key")
#host_key = paramiko.RSAKey.generate(2048)
# host_key = paramiko.DSSKey(filename='test_dss.key')

#file_obj = open("test_rsa.key", "w") 
#host_key.write_private_key(file_obj)

print("Read key: " + u(hexlify(host_key.get_fingerprint())))


class Server(paramiko.ServerInterface):
    # 'data' is the output of base64.b64encode(key)
    # (using the "user_rsa_key" files)
    data = (
        b"AAAAB3NzaC1yc2EAAAABIwAAAIEAyO4it3fHlmGZWJaGrfeHOVY7RWO3P9M7hp"
        b"fAu7jJ2d7eothvfeuoRFtJwhUmZDluRdFyhFY/hFAh76PJKGAusIqIQKlkJxMC"
        b"KDqIexkgHAfID/6mqvmnSJf0b5W8v5h2pI/stOSwTQ+pxVhwJ9ctYDhRSlF0iT"
        b"UWT10hcuO4Ks8="
    )
    data2 = b"AAAAB3NzaC1yc2EAAAADAQABAAACAQDBgsFOvSmvmBiBbfbhtWp/ei4OhY2f+984kVucKkjGBFzebO+xriYGnhT++yfrYfL1s6pIFhg5EnOoBXl8cLAHL0l5WSsukc4jSGKtWZU3EjsLebuL83GKBvuLSacv4caiuMtIM9FKKA2HnKkPi3MVRZSNYuxqPjOkxrQpnGCkqwW8LAHUNTYnDHMFLXY/NAgEYVCwdg+bQga2xKhNUqGZZoMwr5200UWQZgpYgUuQ3fFTsFf4ReOimN7WqbXNKJ7e/8t3p+6pcA8YDLWt9pSXCZEq/Q5NAow0/dsY/BHXHcetHafJlDVi8iMtfZ+qAIBuJoUL642tRRQAfp/26ujtXvnw7Ol8CSkTMdx69sMkHuBwx6Hn3rBQc4+13luwh9Bry/quM06pV2Z94DSTG53Bg1JQugcV81sjrlAJB3y2sNeaLfC2sQAp1YYa5XPB/vi0/WBpgRe8FnDCS5BxO5mJLkc5/LcyenUpYIgHYVwsQiO8OBBEQrwNXsGsDky985gGa4zCEmAZP5L23sX7voCeINvDHpKmJ2gkqxxi2f3AT0N6QToo9ipZHwifDmUdGnBIEtWCBGqDzkyT29sIM+QNYXpWNm43pz+mwN/bb8uWKDoE9dKmDRc6EwYS5XUPc1d/WZDPviRXLQ4fRnWQWmHjCyUoRaaqsUzeENPHu65IxQ=="
    good_pub_key = paramiko.RSAKey(data=decodebytes(data2))

    def __init__(self):
        self.event = threading.Event()

    def check_channel_request(self, kind, chanid):
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_password(self, username, password):
        if (username == "robey") and (password == "foo"):
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def check_auth_publickey(self, username, key):
        print("Auth attempt with key: " + u(hexlify(key.get_fingerprint())))
        if (username == "robey") and (key == self.good_pub_key):
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def check_auth_gssapi_with_mic(
        self, username, gss_authenticated=paramiko.AUTH_FAILED, cc_file=None
    ):
        """
        .. note::
            We are just checking in `AuthHandler` that the given user is a
            valid krb5 principal! We don't check if the krb5 principal is
            allowed to log in on the server, because there is no way to do that
            in python. So if you develop your own SSH server with paramiko for
            a certain platform like Linux, you should call ``krb5_kuserok()`` in
            your local kerberos library to make sure that the krb5_principal
            has an account on the server and is allowed to log in as a user.

        .. seealso::
            `krb5_kuserok() man page
            <http://www.unix.com/man-page/all/3/krb5_kuserok/>`_
        """
        if gss_authenticated == paramiko.AUTH_SUCCESSFUL:
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def check_auth_gssapi_keyex(
        self, username, gss_authenticated=paramiko.AUTH_FAILED, cc_file=None
    ):
        if gss_authenticated == paramiko.AUTH_SUCCESSFUL:
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def enable_auth_gssapi(self):
        return True

    def get_allowed_auths(self, username):
        return "gssapi-keyex,gssapi-with-mic,password,publickey"

    def check_channel_shell_request(self, channel):
        self.event.set()
        return True

    def check_channel_pty_request(
        self, channel, term, width, height, pixelwidth, pixelheight, modes
    ):
        return True


DoGSSAPIKeyExchange = True

# now connect
try:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("", 2200))
except Exception as e:
    print("*** Bind failed: " + str(e))
    traceback.print_exc()
    sys.exit(1)

try:
    sock.listen(100)
    print("Listening for connection ...")
    client, addr = sock.accept()
except Exception as e:
    print("*** Listen/accept failed: " + str(e))
    traceback.print_exc()
    sys.exit(1)

print("Got a connection!")

try:
    #t = paramiko.Transport(client, gss_kex=DoGSSAPIKeyExchange)
    t = paramiko.Transport(client)
    t.set_gss_host(socket.getfqdn(""))
    try:
        t.load_server_moduli()
    except:
        print("(Failed to load moduli -- gex will be unsupported.)")
        raise
    t.add_server_key(host_key)
    server = Server()
    try:
        t.start_server(server=server)
    except paramiko.SSHException:
        print("*** SSH negotiation failed.")
        sys.exit(1)

    # wait for auth
    chan = t.accept(20)
    if chan is None:
        print("*** No channel.")
        sys.exit(1)
    print("Authenticated!")

    server.event.wait(10)
    if not server.event.is_set():
        print("*** Client never asked for a shell.")
        sys.exit(1)

    chan.send("\r\n\r\nWelcome to my dorky little BBS!\r\n\r\n")
    chan.send(
        "We are on fire all the time!  Hooray!  Candy corn for everyone!\r\n"
    )
    chan.send("Happy birthday to Robot Dave!\r\n\r\n")
    chan.send("Username: ")
    f = chan.makefile("rU")
    username = f.readline().strip("\r\n")
    chan.send("\r\nI don't like you, " + username + ".\r\n")
    chan.close()

except Exception as e:
    print("*** Caught exception: " + str(e.__class__) + ": " + str(e))
    traceback.print_exc()
    try:
        t.close()
    except:
        pass
    sys.exit(1)
