# multiSSH

MultiSSH is a server-client application that aims to implement a
teamviewer like experience for SSH. The purpose for this approach is
that you may have infrastructure running behind a firewall/NAT and
therfore not accessible via SSH. You could open up the firwall and
configure port-forwarding rules, but this can be combersome.

Every piece of infrastructure you have behind the firewall can connect
via a client, which will be called "localServer", to a central multiSSH
server on the internet which will be called "remoteServer" (this one has
a public ip and the necessary firewall configuration) The user than
connects to the remoteServer and requests a SSH-Session on one of the
localServers. The remoteServer than connects you to one of the
localServers

There is an old version which is in a working state (master branch) and
a new improved version, that is not ready to be used (branch
restructuring) The restructuring branch is going to replace the master
branch eventually.

This is how the software works:

## master branch

The program consists of three components:

1. localServer.py is a physical machine (has no public ip / behind a
   firewall/nat) that has a running openssh-Server on port 22. It
   connects to the remoteServer and offers a SSH Server to the users
   through forwarding to port 22.
2. remoteServer.py is the central Server (has a public ip / no
   firewall/nat) which receives requests from clients and offers from
   localServers
3. client.py is a client program, which opens a port on the client
   machine. (client machine has no public ip / behind a firewall/nat)
   This port acts like a locally running openssh-Server.

step-by-step operation:

1. remoteServer.py starts up. opens port 2244 on the remoteServer
   machine waits for incomming connections.
2. localServer.py starts up. tries to connect to port 2244 on the
   remoteServer.
3. remoteServer receives offer from localServer. remoteServer safes
   hostname and open socket in a dictonary.
4. client.py starts up on a client machine. client connects to
   remoteServer port 2244. querys the remoteServer for available
   localServers.
5. remoteServer send the client a list of available localServers.
6. client presents the user with list of available localServers. user
   selects a localServer, that he wants to connect to. client sends a
   request for the selected localServer to the remoteServer
7. remoteServer receives the request with the hostname of the
   localServer from the client. then searches its dictonary and finds
   the socket which is connected to the localServer corresponding to the
   hostname
8. remoteServer sends a request for a ssh session to the localServer
9. localServer receives request from remoteServer and opens a connection
   to the locally running openssh-Server on port 22
10. localServer opens a forward from local port 22 to the remoteServer
    over the connected socket.
11. remoteServer opens a forward between the connected localServer and
    the requesting client
12. client opens a socket locally on port 2233 and forwars traffic
    between the connected remoteServer and the local socket.
13. the user now has to connect to localhost port 2233 with a
    ssh-client, like this: `ssh -p 2233 username@localhost` the username
    is the one he wants to use on the localServer machine
14. now an encrypted tunnel exists between localServer, remoteServer and
    client, like this: [openSSH-Server] <-----> [localServer.py] <----->
    [remoteServer.py] <-----> [client.py] <-----> [SSH-Client]
15. once one of the participating programs terminates a forward, the
    whole tunnel collapses and the localServer.py resets and trys to
    establish a new connections to the remoteServer, so a new connection
    from a client can be made.

This approach has a few issues:

1. (most important issue) the hostkey identification for localhost port
   2233 is set on the client machine. however, when the user wants to
   connect to a different localServer the next time, the hostkey
   changes. this causes the ssh-client to refuse the connection. this
   can be solved by always deleting the hostkey. but this is not the way
   it should work.
2. the setup is very complicated for the end-user. he has to firstly
   open the client.py and than has to use a different ssh-client to
   connect to the client.py, whilest the client.py has to be running in
   the background.

to solve these issues the following approach is preferred:

## restructuring branch

the restructuring branch will implement a different approach.

the remoteServer should act like a bastion server
![see here for more info]("https://www.redhat.com/sysadmin/ssh-proxy-bastion-proxyjump")

The user will connect to the remoteServer via a normal ssh-client like
so:

`ssh -J remoteServer username@localServer`

as can be seen, this sends information to the remoteServer, which tells
the remoteServer which localServer the client wants to connect to. The
remoteServer can then initiate a forward between one of the connected
localServers.

In order for the user to be able to see, which localServers are
available, he should be able to connect to the remoteServer like this:

```
$ ssh remoteServer
This is a message from the remoteServer. Here are all available localServers:
localServer1
localServer2
localServer3
```

For this to work, the remoteServer is acting like an actual
openssh-Server. The paramiko library will be used to implement this.

Also the localServer should be able to offer a shell on linux and
windows systems even if there is no locally running openssh-Server. If a
openssh-Server is running on the machine, the localServer should instead
use this server, since it will have alle the features of the
ssh-protocoll
