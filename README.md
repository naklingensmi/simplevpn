simplevpn
---------

Neil Klingensmith
2013-09-14

naklingensmi at wisc dot edu
http://pages.cs.wisc.edu/~klingens

This pair of programs provides simple IP-in-TCP traffic tunneling, similar to
OpenVPN. It uses the linux tun driver, which allows a program to generate
packets instead of a network interface.

It is intended for use in resource-constrained systems for penetrating firewalls
or NATs. Since the code is small and simple, it is easily-extendable.

Usage
-----

To make the program work, you need to have one machine running a server and
another running a client. Compile the server code using:

make srv

Compile the client using:

make cli

1.) Start the server (./srv). Note the IP address of its main network interface.
    For example, 192.168.0.1:

    $ ifconfig eth0

    eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
            inet 192.168.0.1  netmask 255.255.255.0  broadcast 192.168.0.255
            ether xx:xx:xx:xx:xx:xx  txqueuelen 1000  (Ethernet)
            RX packets 21960292  bytes 3371943341 (3.1 GiB)
            RX errors 0  dropped 8105  overruns 4  frame 4
            TX packets 17367322  bytes 2135880048 (1.9 GiB)
            TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0


2.) Start the client with the IP address of the the
    server:

    ./cli -s 192.168.0.1

    The client will get an IP address from the server and configure its tun
    interface and routes correctly. At present, all addresses on the VPN must
    be in the form 10.0.0.0/16.

HOW IT WORKS
------------

The server listens on port 2002 and accepts incoming connections from clients.
The server maintains a list of associated clients. Each element in the list
stores the client's IP address on the VPN as well as a file descriptor for the
socket that it uses to communicate with that client.

When a new client associates to the VPN (by opening a connection with the
server), the server makes a new list entry for the client and spawns a new
thread to handle message passing to and from the client.

When a client thread receives a message from its associated client, it searches
the list of associated clients, looking for one that has an IP address matching
the destination IP of the packet. If it finds a match, it forwards the packet
to that client. If no match is found, it passes the message to the local tun
interface so it can be handled by linux.

IP Address Configuration
------------------------

IP addresses can be assigned automatically by the VPN using a custom protocol.
DHCP cannot be used because it uses lower levels of the OSI stack to exchange
messages, so it is not supported by the Linux TUN driver. Instead simplevpn
implements a custom dynamic address assignment protocol.

Client and server can exchange special messages to configure IP addresses of
new clients. There are two options for IP address assignment: static and
dynamic. Static addresses are requested by the client, and the user can choose
what IP address the client should request by passing an address in on the
command line with the -s option. Dynamic addresses are used if the user does
not request an IP address on the command line.

Assignment Protocol

When the client establishes a connection with the server, the first message it
sends is an IP address request. This consists of an IP packet with no payload
and a destination address of zero. A static address request will have the
requested IP address in the source IP field. A dynamic address request has a
source IP address field of zero. Currently, clients hardcode their netmasks to
255.255.0.0 when setting up the interface. This should be extended to allow the
user to specify the netmask at the server, and the server to push netmask
assignment to the client.

Once the client knows what IP address to use, it must set the interface up with
that address. This is done using a series of ioctl() calls in a function called
set_ip() and add_host_route().


Keepalive Packets
-----------------

Keepalive packets are used by clients to tell the server that they are still
connected to the network. This is useful in environments where clients
frequently go down because of network outages or other problems. If a client
falls off of the network, it will stop sending keepalive packets, and the
server will presume that it is safe to free resources that were previously
allocted for that client (IP address, memory, etc.).

Keepalive packets only need to be sent from client to server if no other
traffic has been sent for a long time. If traffic is being sent regularly,
keepalive packets are not necessary.

Keepalive Packet Structure

Keepalive packets are IPv4 packets with source and destination IP addresses
set to -1:
                                                 src ip    dest ip
                                                .---^---. .---^---.
 |------------------------------------------------------------------|
 | Encap IP Hdr | 4514 0000 0000 0000 4000 0000 ffff ffff ffff ffff | 
 |------------------------------------------------------------------|

Encap IP Hdr is the IP header of the encapsulating packet that is sent over the
physical network interface.

The remainder of the packet (starting with 4514...) is the IP header of the
keepalive packet. The only requirements for this header are that the source IP
and destination IP addresses are both set to -1 (as in the diagram). All other
fields can be anything (zero, garbage data, etc).

When the server receives this packet, it will respond by sending it back to the
client unaltered.

Writing a Client for an Embedded Device
---------------------------------------

Clients should do the following (in order):

0.) Open a TCP socket with the server on port 2002.

1.) Obtain an IP address from the server, statically or dynamically.

2.) Send keepalive packets if no other data is being sent.


