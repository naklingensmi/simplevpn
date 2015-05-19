/* simplevpn-srv.c -- Server for IP-in-TCP tunneling */

/* Copyright (C) 2013 Neil Klingensmith

   This file is part of simplevpn.

   simplevpn is free software: you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public License
   as published by the Free Software Foundation, either version 3 of
   the License, or (at your option) any later version.

   Simpletun is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with simplevpn.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <errno.h>
#include <stdarg.h>
#include <pthread.h>
#include <unistd.h>

// Hard-coded (for now) IP address range+mask to be sure we're handing out valid addresses.
#define IP_MASK  0xffff0000
#define IP_RANGE 0x0a000000


struct client
{
	struct client *next;
	struct client *prev;
	int sockfd;
	int ip;      // IP Addr on the VPN
	int inet_ip; // IP Addr on the internet
	char *key;   // AES Key
};

struct free_ip_addr
{
	struct free_ip_addr *next;
	struct free_ip_addr *prev;
	int address;
};

struct ip_header
{
	char vers;
	char ip_header_len;
	short  packet_len;
	short id;
	short fragment_offset;
	char ttl;
	char protocol;
	short cksum;
	int source_ip;
	int dest_ip;
};

struct client *client_list = NULL;
struct free_ip_addr *free_ip_addr_list = NULL;
pthread_mutex_t client_list_mutex;

/* tun_alloc
 *
 * Creates a tun device. On entry, char *dev points to a character array which
 * tun_alloc fills with the name of the network device it allocates. This code
 * was copied from the kernel documentation.
 */
int tun_alloc(char *dev)
{
	struct ifreq ifr;
	int tun_fd, err;

	if( (tun_fd = open("/dev/net/tun", O_RDWR)) < 0 )
		return -1;

	memset(&ifr, 0, sizeof(ifr));

	/* Flags: IFF_TUN   - TUN device (no Ethernet headers) 
	*         IFF_TAP   - TAP device  
	*
	*         IFF_NO_PI - Do not provide packet information  
	*/ 
	ifr.ifr_flags = IFF_TUN;
	if( *dev )
		strncpy(ifr.ifr_name, dev, IFNAMSIZ);

	if( (err = ioctl(tun_fd, TUNSETIFF, (void *) &ifr)) < 0 ){
		close(tun_fd);
		return err;
	}
	strcpy(dev, ifr.ifr_name);
	return tun_fd;
}

/**************************************************************************
 * cread: read routine that checks for errors and exits if an error is    *
 *        returned.                                                       *
 **************************************************************************/
int cread(int fd, char *buf, int n){
  
  int nread;

  if((nread=read(fd, buf, n))<0){
    perror("Reading data");
    pthread_exit((void*)1);
  }
  return nread;
}

/**************************************************************************
 * cwrite: write routine that checks for errors and exits if an error is  *
 *         returned.                                                      *
 **************************************************************************/
int cwrite(int fd, char *buf, int n){
  
  int nwrite;

  if((nwrite=write(fd, buf, n))<0){
    perror("Writing data");
    pthread_exit((void*)1);
  }
  return nwrite;
}

/**************************************************************************
 * read_n: ensures we read exactly n bytes, and puts those into "buf".    *
 *         (unless EOF, of course)                                        *
 **************************************************************************/
int read_n(int fd, char *buf, int n) {

  int nread, left = n;

  while(left > 0) {
    if ((nread = cread(fd, buf, left))==0){
      return 0 ;      
    }else {
      left -= nread;
      buf += nread;
    }
  }
  return n;  
}


/*
 * generateFreeIPAddressList
 *
 *
 */
unsigned int ip_range_low, ip_range_high, ip_mask;
void generateFreeIPAddressList(int start_addr, int end_addr, int mask)
{
	// Remember allowable IP range. This will be needed later.
	ip_range_low = htonl(start_addr);
	ip_range_high = htonl(end_addr);
	ip_mask = htonl(mask);
	
	while(start_addr <= end_addr)
	{
		struct free_ip_addr *new_ip_addr = malloc(sizeof(struct free_ip_addr));

		if(new_ip_addr == NULL)
		{
			printf("Could not allocate memory in generateFreeIPAddressList\n") ;
			exit(1);
		}

		new_ip_addr->address = htonl(start_addr++);

		while((start_addr & mask) == start_addr)
			start_addr++;

		// Low-order byte of the address can't be 255
		if((start_addr & 0xff) == 0xff || (start_addr & 0xff) == 0)
			start_addr++;
		if((start_addr & 0xff00) == 0xff00 || (start_addr & 0xff00) == 0)
			start_addr += 0x0100 ;

		new_ip_addr->next = free_ip_addr_list;
		free_ip_addr_list = new_ip_addr;
		new_ip_addr->prev = (struct free_ip_addr*)&free_ip_addr_list;
		if(new_ip_addr->next != NULL)
			new_ip_addr->next->prev = new_ip_addr;

	}
}


struct free_ip_addr *findFreeAddr(unsigned int ip_address)
{
	struct free_ip_addr *addr = free_ip_addr_list;
	while((addr != NULL) && (addr->address != ip_address))
		addr = addr->next ;

	return addr ;
}

/*
 * claimIPAddress
 *
 * Deletes an IP address from the free list and returns it. If addr = NULL on
 * entry, claimIPAddress will retrun the first address in the list it finds.
 * This is useful for dynamically allocating addresses to newly connected
 * clients. If addr is non-NULL on entry, claimIPAddress will delete addr from
 * the list of free IP addresses and return addr->address;
 *
 */
unsigned int claimIPAddress(struct free_ip_addr *addr)
{
	unsigned int claimed_address = 0;
	
	fprintf(stderr, "[claimIPAddress] addr = %p\n", addr);
	if(addr != NULL)
	{
		fprintf(stderr, "[claimIPAddress] addr->next = %p\n", addr->next);
		fprintf(stderr, "[claimIPAddress] addr->prev = %p\n", addr->prev);
		fprintf(stderr, "[claimIPAddress] addr->address = %08x\n", addr->address);
	}
	do{
		// Unlink the ip address from the free list.
		if(addr == NULL)
			addr = free_ip_addr_list->next;
		
		addr->prev->next = addr->next;
		if(addr->next != NULL)
			addr->next->prev = addr->prev ;

		claimed_address = addr->address;

		fprintf(stderr, "[claimIPAddress] Freeing addr. addr->address = 0x%08x\n", addr->address);
		fprintf(stderr, "[claimIPAddress] claimed_address = %08x\n", claimed_address);
		fprintf(stderr, "[claimIPAddress] IP_MASK = %08x\n", IP_MASK);
		fprintf(stderr, "[claimIPAddress] IP_RANGE = %08x\n", IP_RANGE);
		free(addr);
	}while((claimed_address & IP_MASK) != IP_RANGE);

	return claimed_address;

}

void cleanup(struct client *cli)
{
	pthread_mutex_lock(&client_list_mutex);
	
	// Check to see if this address is already in the free list. We don't
	// want to add duplicate copies of an IP to the free list.
	struct free_ip_addr *addr = findFreeAddr(cli->ip);
	struct free_ip_addr *addr_iterator;

	// Make sure the address is sane before we re-insert it into the free
	// list. This is kind of a hack. We should probably have a function that
	// checks that the address is within some acceptable range as defined by
	// the address and bitmask since we do this in many places.
	if((addr == NULL) && ((ntohl(cli->ip) & IP_MASK) == IP_RANGE))
	{
		fprintf(stderr, "[cleanup] Reclaiming IP\n");
		// Put the client's address back into the list of free addresses.
		addr = malloc(sizeof(struct free_ip_addr));
		addr_iterator = free_ip_addr_list;
		addr->address = cli->ip;

		while(addr_iterator->next != NULL && ntohl(addr_iterator->next->address) > ntohl(cli->ip))
			addr_iterator = addr_iterator->next;


		// Link the reclaimed address into the list of free addresses.
		addr->next = addr_iterator->next;
		if(addr_iterator->next != NULL)
		{
			addr_iterator->next->prev = addr;
		}
		addr_iterator->next = addr ;
		addr->prev = addr_iterator;

		printf("[cleanup] Old addr linked back into free list after %08x\n", ntohl(addr->prev->address));
	}
	else
	{
		fprintf(stderr,"[cleanup] Problem reclaiming IP address %08x\n", ntohl(cli->ip));
	}

	if(cli->next != NULL)
		cli->next->prev = cli->prev;
	cli->prev->next = cli->next;
	pthread_mutex_unlock(&client_list_mutex);
}

int handleAESKeyExchange(int net_fd)
{
	int i, n;
	char *buffer;
	fd_set rd_set ;
	struct timeval timeout;
	enum {GET_DEV_NAME, SEND_CHALLENGE, RECEIVE_RESPONSE, DONE} keyExchangeState = GET_DEV_NAME;

while(keyExchangeState != DONE)
{
	switch(keyExchangeState)
	{
	case GET_DEV_NAME:
	case RECEIVE_RESPONSE:
		FD_ZERO(&rd_set) ;
		FD_SET(net_fd,&rd_set);

		timeout.tv_sec = 10;
		timeout.tv_usec = 0;

		int ret = select(net_fd + 1, &rd_set, NULL, NULL, &timeout);

		if (ret < 0 && errno == EINTR)
			continue;

		if (ret < 0)
		{
			perror("select()");
			exit(1);
		}

		if(ret == 0)
		{
			// Select timeout.
			printf("Select timeout when getting AES key exchange.\n");
			return -1;
		}

		// If we got data from the net socket...
		if(FD_ISSET(net_fd, &rd_set))
		{
			ioctl(net_fd, FIONREAD,&n);

			buffer = malloc(n+4);
			
			int nread = read(net_fd, buffer, n);

			printf("Received \"%s\" from client\n", buffer);

			// If we just got the node name, send back a challenge.
			if(keyExchangeState == GET_DEV_NAME)
			{
				write(net_fd, buffer, strlen(buffer)+1);
				keyExchangeState = RECEIVE_RESPONSE;
			}
			else
			{
				// perform md5, etc...
				printf("Performing MD5 hash on challenge and comparing to response from client...\n");
				keyExchangeState = DONE;
			}

			free(buffer);

		}
		else
		{
			fprintf(stderr, "Key exchange failed in select()\n");
			return -3;
		}
		break;
	case SEND_CHALLENGE:
		break;
	default:
		return -2;
	}
}
	return 0;
}

/*
 * handleConnectionThread
 *
 * This is the main thread that handles connections from clients. This just
 * runs in a loop, listening for a packet from a client, and then sends the
 * packet to its destination.
 * 
 * IP addresses are stored in data structures in network byte order to reduce
 * the number of calls to htonl() and ntohl() etc. The only time they need to
 * be converted to host byte order is if two addresses are being compared for
 * greater than/less than. Equality comparisons don't need to convert addresses
 * from network order to host order.
 */
void *handleConnectionThread(void *c)
{
	int n;
	struct client *cli = (struct client*)c;
	int net_fd = cli->sockfd;
	char *buffer ;
	unsigned short nread;
	struct timeval timeout;
	int pass = 0;

	timeout.tv_sec = SOCK_TIMEOUT/2;
	timeout.tv_usec = 0;

	if (setsockopt (net_fd, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout,sizeof(timeout)) < 0)
	{
		perror("setsockopt()");
		exit(1) ;
	}

	if (setsockopt (net_fd, SOL_SOCKET, SO_SNDTIMEO, (char *)&timeout,sizeof(timeout)) < 0)
	{
		perror("setsockopt()");
	}
	
	handleAESKeyExchange(net_fd);
	
	int maxfd = net_fd;	
	while(1)
	{
		fd_set rd_set ;

		FD_ZERO(&rd_set) ;
		FD_SET(net_fd,&rd_set);

		timeout.tv_sec = 60;
		timeout.tv_usec = 0;

		int ret = select(maxfd + 1, &rd_set, NULL, NULL, &timeout);

		if (ret < 0 && errno == EINTR)
			continue;

		if (ret < 0)
		{
			perror("select()");
			exit(1);
		}

		if(ret == 0)
		{
			// Select timeout.
			printf("Select timeout. Removing address %08x\n", ntohl(cli->ip));
			cleanup(cli);
			free(cli);
			close(net_fd);
			pthread_exit(0);
		}

		if(FD_ISSET(net_fd, &rd_set))
		{
			// Find out how many bytes are available to read from the
			// network fd.
			ioctl(net_fd, FIONREAD,&n);

			buffer = malloc(n+4);

			if(n == 0)
			{
				// Connection closed by remote host.
				printf("Disconnect from %s (%08x)\n",inet_ntoa(*(struct in_addr*)&cli->inet_ip), ntohl(cli->ip));
				cleanup(cli);
				free(cli);
				close(net_fd);
				pthread_exit(0);
			}

			// read packet, four bytes in to buffer to account for packet
			// information header that gets prepended to every tun packet.
			nread = read(net_fd, buffer, n);

			if(pass == 0)
			{
				handleAESKeyExchange(net_fd);

				if(nread > strlen(buffer))
				{
					memcpy(buffer,buffer+strlen(buffer), nread-strlen(buffer));
					nread -= 32;
				}
				else
				{
					free(buffer);
					printf("moving on\n");
					continue;
				}
				pass = 1;
			}

			// When we get a packet from one of the associated VPN
			// clients, check out list of associated devices to see
			// if one of them has an IP address that matches the
			// destination IP of the packet we just received. If we
			// find one, forward the packet to that client.
			// Otherwise, send the packet to the tun interface and
			// let linux deal with it.
			pthread_mutex_lock(&client_list_mutex);

			struct ip_header *iphdr = (struct ip_header*)(buffer);
			struct client *iterator = (struct client*)&client_list;

			// If the client has a self-assigned IP in the correct
			// range, then record it.
			if((ntohl(iphdr->source_ip) >= ip_range_low) && (ntohl(iphdr->source_ip) <= ip_range_high) && iphdr->dest_ip != 0 && iphdr->dest_ip != -1)
			{
				struct free_ip_addr *addr = findFreeAddr(iphdr->source_ip);
				cli->ip = iphdr->source_ip; // Set address.
				if(addr != NULL)
				{
					printf("Client has self-assigned IP that is in free list: %08x...\n", ntohl(iphdr->source_ip));
					claimIPAddress(addr);
					printf("Returned from claimIPAddress\n");
				}

			}
			if((ntohl(iphdr->source_ip) == 0) && (ntohl(iphdr->dest_ip) == 0))
			{
				// Address request.
				// If the client does not already have an
				// address, assign it one.
				if(cli->ip == -1)
				{
					// Unlink the ip address from the free list.
					struct free_ip_addr *addr = free_ip_addr_list;
					free_ip_addr_list = free_ip_addr_list->next ;
					if(free_ip_addr_list != NULL)
						free_ip_addr_list->prev = (struct free_ip_addr*)&free_ip_addr_list;
					
					cli->ip = addr->address; // Set address.
					free(addr);
				}
				// Otherwise, just respond with the IP it is
				// already assigned.
				iphdr->dest_ip = cli->ip ;

				printf("Got address request. Assigning 0x%08x\n", ntohl(cli->ip));
				int err = write(cli->sockfd, buffer, nread);
				if(err <= 0)
					printf("nothing written to cli sockfd\n");

			}
			else if((ntohl(iphdr->source_ip) != 0) && (ntohl(iphdr->dest_ip) == 0))
			{
				// Static address request.
				// Find the requested IP address in the list.

				struct free_ip_addr *addr = findFreeAddr(iphdr->source_ip);
				if((addr != NULL) && (addr->address == iphdr->source_ip))
				{
					// Unlink the address from the list.
					addr->prev->next = addr->next;
					if(addr->next != NULL)
						addr->next->prev = addr->prev;
					
					free(addr) ;
					// Static IP on client side.
					iphdr->dest_ip = iphdr->source_ip ;
					iphdr->source_ip = 0 ;

					// Record the client's IP in the cli struct
					cli->ip = iphdr->dest_ip;
				}
				else
				{
					// Address in use
					fprintf(stderr,"ERROR: Client requested a static address that is already in use: %08x\n", ntohl(iphdr->source_ip));
					iphdr->dest_ip = 0 ; // Indicate error
					iphdr->source_ip = 0 ;

					pthread_mutex_unlock(&client_list_mutex);

					cli->ip = -1;
					fprintf(stderr, "[handleConnectionThread] Calling cleanup()\n");
					cleanup(cli);
					fprintf(stderr, "[handleConnectionThread] Returned from cleanup()\n");
					free(cli);
					close(net_fd);


					fprintf(stderr, "[handleConnectionThread] Unlocking client_list_mutex\n");

					pthread_exit((void*)1);
				}


				// Acknowledge static IP assignment
				int err = write(cli->sockfd, buffer, nread);
				if(err <= 0)
					fprintf(stderr,"nothing written to cli sockfd\n");

			}
			else if((ntohl(iphdr->source_ip) == -1) && (ntohl(iphdr->dest_ip) == -1))
			{
				// Keepalive
				int err = write(cli->sockfd, buffer, nread) ;
				if(err < 0)
					printf("Write error\n") ;
			}
			// Look thru the list of connected clients and see if
			// there is an IP address match. If so, send the packet
			// to the intended client.
			while(iterator->next != NULL)
			{
				if(iterator->next->ip == iphdr->dest_ip)
				{
					// Found the correct device in the list
					int err = write(iterator->next->sockfd, buffer, nread);
					if(err <= 0)
						printf("nothing written to cli sockfd\n");


					break;
				}

				// If we haven't found it yet, keep looking.
				iterator = iterator->next;
			}
			pthread_mutex_unlock(&client_list_mutex);
			free(buffer);
		}
	}
}

/*
 * findKey
 *
 * Search keyfilefd for AES key associated with devname.
 * 
 */
#define KEYFILE_LINE_MAX 2048
int findKey(FILE *keyfilefd, char *devname, char **key)
{
	char *devid = malloc(1000);
	int nargs;
	
	while(1)
	{
		nargs = fscanf(keyfilefd, "%s %s\n", devid, *key);

		if(nargs == EOF)
			break;
		else if(nargs != 2)
			continue;

		if(strcmp(devid, devname) == 0)
		{
			free(devid);
			return 0;
		}
		printf("nargs = %d devid = \"%s\" devkey = \"%s\"\n", nargs, devid, *key);
	}

	free(devid);
	return -1;
}

void usage(char *progname)
{
	printf("%s: simpleVPN client application\n\n", progname);
	printf("\t-k\t\tRequired. Keyfile location. See README.md for format.\n");
	printf("\t-u\t\tOptional. Use UDP instead of TCP. Not implemented\n");
	printf("\t-p <port>\tOptional. Set the local port to listen on.\n");
	printf("\n");
}

int main(int argc, char ** argv)
{
	char *devname = malloc(50) ;
	char *str = malloc(50) ;
	char *keyfilepath = NULL;
	int net_fd = 0, sock_fd = 0, optval = 1 ;
	struct sockaddr_in local, remote;
	socklen_t remotelen;
	unsigned short port = 2002;
	unsigned int socktype = SOCK_STREAM;
	int c;
	FILE *keyfilefd = 0;

	generateFreeIPAddressList(0x0a000001, 0x0a00ffff, 0xfffff000);
	
	pthread_mutex_init(&client_list_mutex, NULL);

	while ((c = getopt (argc, argv, "up:k:")) != -1)
	{
		switch (c)
		{
		case 'u':
			printf("Connecting to server using UDP\n");
			socktype = SOCK_DGRAM;
			break;
		case 'p':
			port = atoi(optarg);
			break;
		case 'k':
			keyfilepath = malloc(strlen(optarg)+2);
			strcpy(keyfilepath, optarg);
			break;
		default:
			usage(argv[0]);
			printf("Unrecognized option %c\n", c);
			return -1;
		}
	}

	if(keyfilepath == NULL)
	{
		usage(argv[0]);
		fprintf(stderr, "ERROR: No key file specified.\n");
		exit(1);
	}

	keyfilefd = fopen(keyfilepath, "r");
	if(keyfilefd < 0)
	{
		perror("fopen()");
		exit(1) ;
	}

	// Set up socket to listen on
	if ( (sock_fd = socket(AF_INET, socktype, 0)) < 0)
	{
		perror("socket()");
		exit(1);
	}
	
	// avoid EADDRINUSE error on bind()
	if(setsockopt(sock_fd, SOL_SOCKET, SO_REUSEADDR, (char *)&optval, sizeof(optval)) < 0)
	{
		perror("setsockopt()");
		exit(1);
	}

	memset(&local, 0, sizeof(local));
	local.sin_family = AF_INET;
	local.sin_addr.s_addr = htonl(INADDR_ANY);
	local.sin_port = htons(port);
	if (bind(sock_fd, (struct sockaddr*) &local, sizeof(local)) < 0)
	{
		perror("bind()");
		exit(1);
	}

	if(socktype == SOCK_DGRAM)
	{
		//UDP socket
	}

	if (listen(sock_fd, 5) < 0)
	{
		perror("listen()");
		exit(1);
	}
	while(1)
	{
		// wait for connection request
		remotelen = sizeof(remote);
		memset(&remote, 0, remotelen);
		if ((net_fd = accept(sock_fd, (struct sockaddr*)&remote, &remotelen)) < 0)
		{
			perror("accept()");
			exit(1);
		}

		printf("SERVER: Client connected from %s\n", inet_ntoa(remote.sin_addr));
		
		// Spawn a new thread to handle the connection.
		pthread_t *th = malloc(sizeof(pthread_t)) ;


		struct client *newclient = malloc(sizeof(struct client));
		newclient->sockfd = net_fd;
		newclient->ip = 0x0a000002; // Dummy IP address.
		newclient->inet_ip = remote.sin_addr.s_addr;
		
		// Link newclient into list of assoc'd clients.
		pthread_mutex_lock(&client_list_mutex);
		newclient->next = client_list;
		client_list = newclient;
		newclient->prev = (struct client*)&client_list;
		if(newclient->next != NULL)
			newclient->next->prev = newclient;

		newclient->ip = -1;
		pthread_mutex_unlock(&client_list_mutex);

		pthread_create(th, NULL, handleConnectionThread, (void*)newclient) ;
	}
	// Clean up
	free(devname) ;
	free(str);
//	close(tun_fd);
}

