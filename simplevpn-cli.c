
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
//#include <sys/types.h>
//#include <sys/stat.h>
#include <arpa/inet.h>
//#include <sys/select.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <errno.h>
#include <stdarg.h>
#include <unistd.h>
#include <net/route.h>
#include <netdb.h>


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
	ifr.ifr_flags = IFF_TUN | IFF_NO_PI ;
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
    exit(1);
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
    exit(1);
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

static void init_sockaddr_in(struct sockaddr *sa, in_addr_t addr)
{
	struct sockaddr_in *sin = (struct sockaddr_in *) sa;
	sin->sin_family = AF_INET;
	sin->sin_port = 0;
	sin->sin_addr.s_addr = addr;
}

/*
 * add_host_route
 *
 * Add an entry to the routing table through interface "name".
 */
int add_host_route(const char *name, in_addr_t addr)
{
	struct rtentry rt;
	int result;
	int sockfd = socket(AF_INET, SOCK_STREAM, 0);

	memset(&rt, 0, sizeof(rt));

	rt.rt_dst.sa_family = AF_INET;
	rt.rt_flags = RTF_UP | RTF_HOST;
	rt.rt_dev = (void*) name;
	init_sockaddr_in(&rt.rt_dst, addr);
	init_sockaddr_in(&rt.rt_genmask, 0);
	init_sockaddr_in(&rt.rt_gateway, 0);

	result = ioctl(sockfd, SIOCADDRT, &rt);
	if (result < 0 && errno == EEXIST) {
		result = 0;
	}
	
	close(sockfd) ;
	return result;
}

/*
 * set_ip
 *
 * Configure the IP address for interface "name".
 */
static int set_ip(const char *name, unsigned int ip, unsigned int mask)
{
	struct ifreq ifr;
	struct sockaddr_in sin;
	int sockfd = socket(AF_INET, SOCK_STREAM, 0);
	int err;

	strncpy(ifr.ifr_name, name, IFNAMSIZ);

	// Get interface properties in ifr
	err = ioctl(sockfd, SIOCGIFFLAGS, &ifr);
	if(err < 0)
		perror("ioctl 1") ;

	// Bring the interface up.
	ifr.ifr_flags |= IFF_UP | IFF_RUNNING;

	err = ioctl(sockfd, SIOCSIFFLAGS, &ifr);
	if(err < 0)
		perror("ioctl 2");
	
	strncpy(ifr.ifr_name, name, IFNAMSIZ);
	memset(&sin, 0, sizeof(struct sockaddr));
	sin.sin_family = AF_INET;
	sin.sin_port = 0 ;
	sin.sin_addr.s_addr = htonl(ip);
	memcpy(&ifr.ifr_addr, &sin, sizeof(struct sockaddr));
	err = ioctl(sockfd, SIOCSIFADDR, &ifr);

	if(err < 0)
	{
		perror("ioctl 3" );
		return -1;
	}
	
	sin.sin_family = AF_INET;
	sin.sin_port = 0 ;
	sin.sin_addr.s_addr = htonl(mask);
	memcpy(&ifr.ifr_netmask, &sin, sizeof(struct sockaddr));
	err = ioctl(sockfd, SIOCSIFNETMASK, &ifr);
	
	if(err < 0)
	{
		perror("ioctl 4" );
		return -1;
	}

	close(sockfd) ;

	return 0;
}

int register_static_ip(int net_fd, int ip, char *devname)
{
	char *buffer;
	int nread;

	// Static IP
	buffer = malloc(100);
	struct ip_header *iphdr = (struct ip_header*)buffer;
	memset(buffer,0,100);
	iphdr->vers = 0x45;
	iphdr->ip_header_len = 20;
	iphdr->ttl = 64;
	iphdr->source_ip = ip;
	if(cwrite(net_fd, buffer, 20) <= 0)
	{
		printf("error: write failed while requesting static IP address from server.\n");
		exit(1);
	}

	nread = cread(net_fd, buffer, 100) ;

	if(nread == 0)
	{
		// Connection closed while trying to assign a statick IP. This means that someone else already has that address.
		fprintf(stderr, "ERROR: Requested static IP address already in use.\n");
		exit(0);
	}

	set_ip(devname, ntohl(iphdr->dest_ip), 0xffff0000);
	if(add_host_route(devname, (in_addr_t)ntohl(iphdr->dest_ip)) < 0)
		printf("add_host_route returned\n");

	// Set the interface address.
	free(buffer) ;

	return 0;
}


int get_ip_from_server(int net_fd, char *devname)
{
	char *buffer;

	// Get IP Address from server
	buffer = malloc(100) ;
	struct ip_header *iphdr = (struct ip_header*)buffer ;
	memset(buffer,0,100) ;
	iphdr->vers = 0x45 ;
	iphdr->ip_header_len = 20 ;
	iphdr->ttl = 64;
	printf("sending IP request\n");
	if(cwrite(net_fd, buffer, 20) <= 0)
	{
		printf("error: write failed while getting IP address from server\n");
		exit(1);
	}

	cread(net_fd, buffer, 100) ;
	printf("Got IP response: %08x\n", ntohl(iphdr->dest_ip)) ;

	set_ip(devname, ntohl(iphdr->dest_ip), 0xffff0000);

	// Set the interface address.
	free(buffer) ;

	return 0;
}

/*
 * usage
 *
 * Prints the usage information for the program.
 */
void usage(char *progname)
{
	printf("%s: simpleVPN client application\n\n", progname);
	printf("\t-s <server ip>\tRequired. Specify server address\n");
	printf("\t-a <local ip>\tOptional. Request static address on the VPN\n");
	printf("\t-p <port>\tOptional. Specify port on which the server listens.\n");
	printf("\t-u\t\tOptional. Use UDP instead of TCP. NOT IMPLEMENTED.\n");

	printf("\n");
}

int main(int argc, char **argv)
{
	char *devname = malloc(IFNAMSIZ+1) ;
	char *str = malloc(50) ;
	char *buffer ;
	char *port_str = NULL;
	int tun_fd = tun_alloc(devname) ;
	int net_fd = 0, sock_fd = 0;
	unsigned int ip = 0;
	struct sockaddr_in remote;
	unsigned short port = 2002;
	char *server_domain = NULL;
	unsigned short nread;
	int n;
	int socktype = SOCK_STREAM;
	int c ;
	struct addrinfo *hints = malloc(sizeof(struct addrinfo));
	struct addrinfo *result = malloc(sizeof(struct addrinfo));
	char key[16];
	char *nodename = NULL;

	while ((c = getopt (argc, argv, "us:a:p:n:k:")) != -1)
	{
		switch (c)
		{
		case 'a':
			ip = inet_addr(optarg) ;
			break ;
		case 's':
			server_domain = malloc(strlen(optarg)+2);
			strcpy(server_domain, optarg);
			break ;
		case 'u':
			socktype = SOCK_DGRAM;
			break;
		case 'p':
			port = atoi(optarg);
			break;
		case 'n':
			nodename = malloc(strlen(optarg) + 2);
			strcpy(nodename,optarg);
			break;
		case 'k':
			for(n = 0 ; n < 16 ; n++)
			{
				key[n] = (optarg[2*n] > '9' ? (optarg[2*n] > 'F' ? optarg[2*n] - 'a'+10 : optarg[2*n] - 'A'+10) : optarg[2*n] - '0') << 4;
				key[n] |= (optarg[2*n+1] > '9' ? (optarg[2*n+1] > 'F' ? optarg[2*n+1] - 'a'+10 : optarg[2*n+1] - 'A'+10) : optarg[2*n+1] - '0');
			}

			for(n = 0 ; n < 16 ; n++)
				printf("%02x ", (int)(key[n] & 0xff));

			break;
		default:
			usage(argv[0]);
			printf("Unrecognized option %c\n", c);
			return -1;
		}
	}

	if(server_domain == NULL)
	{
		usage(argv[0]);
		printf("Please specify a server using the -s argument\n");
		return -1 ;
	}

	if(tun_fd <= 0)
	{
		printf("Could not create tun device.\nPlease make sure you are running as root and that the tun kernel module is loaded.\n") ;
		return -1;
	}

	if ( (sock_fd = socket(AF_INET, socktype, 0)) < 0) {
		perror("socket()");
		exit(1);
	}

	// Look up the IP address associated with the user-supplied domain
	memset(hints, 0, sizeof(struct addrinfo));
	hints->ai_family = AF_UNSPEC;
	hints->ai_socktype = SOCK_DGRAM;
	hints->ai_flags = AI_PASSIVE;
	hints->ai_protocol = 0;
	hints->ai_canonname = NULL;
	hints->ai_addr = NULL;
	hints->ai_next = NULL;
	port_str = malloc(20);
	sprintf(port_str, "%d", (int)(port & 0xffff));
	getaddrinfo(server_domain, port_str, hints, &result);
	memcpy(&remote, result->ai_addr, sizeof(struct sockaddr_in));

	// connection request
	if (connect(sock_fd, (struct sockaddr*) &remote, sizeof(remote)) < 0)
	{
		perror("connect()");
		exit(1);
	}

	net_fd = sock_fd;
	printf("CLIENT: Connected to server %s\n", inet_ntoa(remote.sin_addr));

	// Send client ID
	buffer = malloc(strlen(nodename)+2);
	memset(buffer,0,strlen(nodename)+2);
	strcpy(buffer, nodename);
	if(cwrite(net_fd, buffer, 32) <= 0)
	{
		printf("error: write failed while sending AES key to server\n");
		exit(1);
	}
	free(buffer);
	
	// Receive a challenge...
	fd_set rd_set ;
	struct timeval timeout;

	// If we come close to timing out, we will send a keep-alive packet.
	timeout.tv_sec = SOCK_TIMEOUT / 4;
	timeout.tv_usec = 0;

	FD_ZERO(&rd_set) ;
	FD_SET(net_fd,&rd_set);

	int ret = select(net_fd + 1, &rd_set, NULL, NULL, &timeout);

	if (ret < 0)
	{
		perror("select()");
		exit(1);
	}
	ioctl(net_fd, FIONREAD,&n);

	buffer = malloc(n+4);
	
	nread = read(net_fd, buffer, n);
	printf("Challenge: Got \"%s\" from server\n", buffer);


	if(ip == 0)
	{
		get_ip_from_server(net_fd, devname);
	}
	else
	{
		register_static_ip(net_fd, ip, devname);
	}
	int maxfd = (tun_fd > net_fd)?tun_fd:net_fd;
	
	while(1)
	{
		fd_set rd_set ;
		struct timeval timeout;

		// If we come close to timing out, we will send a keep-alive packet.
		timeout.tv_sec = SOCK_TIMEOUT / 4;
		timeout.tv_usec = 0;

		FD_ZERO(&rd_set) ;
		FD_SET(tun_fd,&rd_set) ;
		FD_SET(net_fd,&rd_set);

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
			// Timeout
			buffer = malloc(100) ;
			struct ip_header *iphdr = (struct ip_header*)buffer ;
			memset(buffer,0,100) ;
			iphdr->vers = 0x45 ;
			iphdr->ip_header_len = 20 ;
			iphdr->ttl = 64;
			iphdr->dest_ip = -1 ;
			iphdr->source_ip = -1;
			
			do
			{
				// Send keepalive
				if(cwrite(net_fd, buffer, 20) <= 0)
				{
					printf("error: cwrite failed while sending keepalive\n");
					exit(1);
				}
				
				timeout.tv_sec = 1;
				timeout.tv_usec = 0;

				FD_ZERO(&rd_set) ;
				FD_SET(net_fd,&rd_set);
			}while(select(maxfd + 1, &rd_set, NULL, NULL, &timeout) == 0);

			// Set the interface address.
			free(buffer) ;
			continue;
		}

		if(FD_ISSET(tun_fd, &rd_set))
		{
			buffer = malloc(2000);
			*(int*)buffer = 0 ;
			/* data from tun/tap: just read it and write it to the network */

			nread = cread(tun_fd, buffer, 2000);

			/* write length + packet */
			if(cwrite(net_fd, buffer, nread) <= 0)
			{
				printf("error: writing to net_fd\n");
				exit(1) ;
			}
			free(buffer);
		}

		if(FD_ISSET(net_fd, &rd_set))
		{
			ioctl(net_fd, FIONREAD,&n);

			buffer = malloc(n);
			*(int*) buffer = 0 ;

			if(n == 0)
			{
				printf("Connection closed by remote host.\n");
	close(sock_fd) ;

	while ( (sock_fd = socket(AF_INET, socktype, 0)) < 0) {
		perror("socket()");
		sleep(1) ;
	}

	// Look up the IP address associated with the user-supplied domain
	memset(hints, 0, sizeof(struct addrinfo));
	hints->ai_family = AF_UNSPEC;
	hints->ai_socktype = SOCK_DGRAM;
	hints->ai_flags = AI_PASSIVE;
	hints->ai_protocol = 0;
	hints->ai_canonname = NULL;
	hints->ai_addr = NULL;
	hints->ai_next = NULL;
	getaddrinfo(server_domain, "2002", hints, &result);
	memcpy(&remote, result->ai_addr, sizeof(struct sockaddr_in));

	// Attempt to reconnect.
	while (connect(sock_fd, (struct sockaddr*) &remote, sizeof(remote)) < 0)
	{
		perror("connect()");
		sleep(1) ;
	}

	net_fd = sock_fd;
	printf("CLIENT: Connected to server %s\n", inet_ntoa(remote.sin_addr));

	// Re-register the IP address with the server after we have reconnected.
	register_static_ip(net_fd, ip, devname);
				sleep(2) ;
				continue ;
			}

			// read packet
			nread = read(net_fd, buffer, n);

			// now buffer[] contains a full packet or frame, write it into the tun/tap interface
			if(write(tun_fd, buffer, nread) <= 0)
			{
				printf("tun_fd = %08x buffer = %p nread = %d\n", tun_fd, buffer, nread) ;
				perror("write to tun_fd") ;
			}
			free(buffer);
		}
	}

	// Clean up
	free(devname) ;
	free(str);
	close(sock_fd);
	return 0 ;
}

