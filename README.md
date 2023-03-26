# multiSSH

MultiSSH is a server-client application that aims to implement a teamviewer like experience for SSH
There is an old version which is in a working state (master branch) and a new improved version, that is not ready to be used (branch restructuring)
The restructuring branch is going to replace the master branch eventually.

This is how the software works:

## master branch

The program consists of three components:

1. localServer.py is a physical machine (has no public ip / behind a firewall/nat) that has a running openssh-Server on port 22. It connects to the remoteServer and offers a SSH Server to the users through forwarding to port 22.
2. remoteServer.py is the central Server (has a public ip / no firewall/nat) which receives requests from clients and offers from localServers
3. client.py is a client program, which opens a port on the client machine. (client machine has no public ip / behind a firewall/nat) This port acts like a locally running openssh-Server.

step-by-step operation:

1. remoteServer.py starts up. opens port 2244 on the remoteServer machine waits for incomming connections.
2. localServer.py starts up. tries to connect to port 2244 on the remoteServer.
3. remoteServer receives offer from localServer. remoteServer safes hostname and open socket in a dictonary.
4. client.py starts up on a client machine. client connects to remoteServer port 2244. querys the remoteServer for available localServers.
5. remoteServer send the client a list of available localServers.
6. client presents the user with list of available localServers. user selects a localServer, that he wants to connect to. client sends a request for the selected localServer to the remoteServer
7. remoteServer receives the request with the hostname of the localServer from the client. then searches its dictonary and finds the socket which is connected to the localServer corresponding to the hostname
8. remoteServer sends a request for a ssh session to the localServer
9. localServer receives request from remoteServer and opens a connection to the locally running openssh-Server on port 22
10. localServer opens a forward from local port 22 to the remoteServer over the connected socket.
11. remoteServer opens a forward between the connected localServer and the requesting client
12. client opens a socket locally on port 2233 and forwars traffic between the connected remoteServer and the local socket.
13. the user now has to connect to localhost port 2233 with a ssh-client, like this: `ssh -p 2233 username@localhost` the username is the one he wants to use on the localServer machine
14. now an encrypted tunnel exists between localServer, remoteServer and client, like this: [openSSH-Server] <-----> [localServer.py] <-----> [remoteServer.py] <-----> [client.py] <-----> [SSH-Client] 
15. once one of the participating programs terminates a forward, the whole tunnel collapses and the localServer.py resets and trys to establish a new connections to the remoteServer, so a new connection from a client can be made.

This approach has a few issues:

1. (most important issue) the hostkey identification for localhost port 2233 is set on the client machine. however, when the user wants to connect to a different localServer the next time, the hostkey changes. this causes the ssh-client to refuse the connection. this can be solved by always deleting the hostkey. but this is not the way it should work.
2. the setup is very complicated for the end-user. he has to firstly open the client.py and than has to use a different ssh-client to connect to the client.py, whilest the client.py has to be running in the background.

to solve these issues the following approach is preferred:

## restructuring branch


