#include "network.h"

char s[INET6_ADDRSTRLEN];

/*
Socket Functions
*/
void sigchld_handler(int s)
{
	(void)s; // quiet unused variable warning

	// waitpid() might overwrite errno, so we save and restore it:
	int saved_errno = errno;

	while(waitpid(-1, NULL, WNOHANG) > 0);

	errno = saved_errno;
}


// get sockaddr, IPv4 or IPv6:
void *get_in_addr(struct sockaddr *sa)
{
	if (sa->sa_family == AF_INET) {
		return &(((struct sockaddr_in*)sa)->sin_addr);
	}

	return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

/*
Establish a TCP socket to listen for messages on
*/
int get_server_tcp_socket(char* port)
{
	int sockfd; 
	struct addrinfo hints, *servinfo, *p;
	int rv;
	int yes=1;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE;

	rv = getaddrinfo(NULL, port, &hints, &servinfo);
	if(rv != 0){
		fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
		exit(EXIT_FAILURE);
	}

	// loop through all the results and bind to the first we can
	for(p = servinfo; p != NULL; p = p->ai_next) {
		if ((sockfd = socket(p->ai_family, p->ai_socktype,
				p->ai_protocol)) == -1) {
			perror("server: socket");
			continue;
		}

		if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes,
				sizeof(int)) == -1) {
			perror("setsockopt");
			exit(1);
		}

		if (bind(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
			close(sockfd);
			perror("server: bind");
			continue;
		}
		break;
	}
	freeaddrinfo(servinfo);
	if(p == NULL){
		fprintf(stderr, "failed to bind\n");
		return -1;
	}
	return sockfd;
}

void set_reap_handler(){
	struct sigaction sa;
	sa.sa_handler = sigchld_handler; // reap all dead processes
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = SA_RESTART;
	if (sigaction(SIGCHLD, &sa, NULL) == -1) {
		perror("sigaction");
		exit(1);
	}// Client Functions
}

/*
Listen on the passed in socket and set up our dead connection reap handler
*/
void listen_on_sock(int sockfd, int backlog_count){
	int rv = listen(sockfd, backlog_count);
	if(rv == -1){
		fprintf(stderr, "error listening on socket with fd %d", sockfd);
		exit(EXIT_FAILURE);
	}
	set_reap_handler();
}

/*
Wait for a connection on the passed in socket file descriptor and return
the live connection file descriptor once we get a message
*/
int get_connection_socket(int sockfd)
{
	int newfd;
	struct sockaddr_storage their_addr;
	socklen_t sin_size;
	sin_size = sizeof their_addr;
	newfd = accept(sockfd, (struct sockaddr *)&their_addr, &sin_size);
	if(newfd == -1){
		return -1;
	}
	inet_ntop(their_addr.ss_family,
				get_in_addr((struct sockaddr *)&their_addr),
				s, sizeof s);
	printf("server: got connection from %s\n", s);
	return newfd;
}

/*
Create a client TCP socket and return its file descriptor 
*/
int get_client_tcp_socket(char* port, char* nodename){
	int sockfd; 
	struct addrinfo hints, *servinfo, *p;
	int rv;

	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;

	if ((rv = getaddrinfo(nodename, port, &hints, &servinfo)) != 0) {
		fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
		return 1;
	}

	// loop through all the results and connect to the first we can
	for(p = servinfo; p != NULL; p = p->ai_next) {
		if ((sockfd = socket(p->ai_family, p->ai_socktype,
				p->ai_protocol)) == -1) {
			perror("client: socket");
			continue;
		}

		if (connect(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
			perror("client: connect");
			close(sockfd);
			continue;
		}
		break;
	}
	inet_ntop(p->ai_family, get_in_addr((struct sockaddr *)p->ai_addr),
		s, sizeof s);
	printf("client: connecting to %s\n", s);
	return sockfd;
}

/*
Create a UDP port and return its file descriptor. This hosts info will be stored in info
Param:
	port: the port we want the socket to listen on
	info: the info of the host (ourself)
*/
int get_server_udp_socket(const char* port, struct addrinfo* info){
	int sockfd;
	struct addrinfo hints, *servinfo, *p;
	int rv;

	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_UNSPEC; // set to AF_INET to use IPv4
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_flags = AI_PASSIVE; // use my IP

	if ((rv = getaddrinfo(NULL, port, &hints, &servinfo)) != 0) {
		fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
		return 1;
	}

	// loop through all the results and bind to the first we can
	for(p = servinfo; p != NULL; p = p->ai_next) {
		if ((sockfd = socket(p->ai_family, p->ai_socktype,
				p->ai_protocol)) == -1) {
			perror("listener: socket");
			continue;
		}

		if (bind(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
			close(sockfd);
			perror("listener: bind");
			continue;
		}

		break;
	}

	if (p == NULL) {
		fprintf(stderr, "server: failed to bind socket\n");
		return -1;
	}

	freeaddrinfo(servinfo);
	info->ai_addr = p->ai_addr;
	info->ai_addrlen = p ->ai_addrlen;
	return sockfd;
}

/*
Create a UDP socket and return its file descriptor. This socket will send to the hostname and port supplied as arguments.
Params: 
	port: the port number we want to sent to over this socket 
	hostname: the hostname we want to send to 
	info: the addrinfo of the host we want to send to, populated once this function returns 
*/
int get_client_udp_socket(const char* port, const char* hostname, struct addrinfo* info){
 	int sockfd;
    struct addrinfo hints, *servinfo, *p;
    int rv;

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC; // set to AF_INET to use IPv4
    hints.ai_socktype = SOCK_DGRAM;

    if ((rv = getaddrinfo(hostname, port, &hints, &servinfo)) != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
        return 1;
    }

    // loop through all the results and make a socket
    for(p = servinfo; p != NULL; p = p->ai_next) {
        if ((sockfd = socket(p->ai_family, p->ai_socktype,
                p->ai_protocol)) == -1) {
            perror("talker: socket");
            continue;
        }

        break;
    }

    if (p == NULL) {
        fprintf(stderr, "talker: failed to create socket\n");
        return 2;
    }

	info->ai_addr = p->ai_addr;
	info->ai_addrlen = p->ai_addrlen;
	return sockfd;
}

/*
Get a udp packet, and return the sockaddr struct containing info about the sender
Also, stores the addrlength returned from recvfrom into addr_length
Params:
	sockfd: the UDP socket to get data from
	buf: the buffer to store the message in
	addr_length: address of a socken_t to store the address length from the call to recvfrom in
*/
struct sockaddr get_udp_packet(int sockfd, char* buf, socklen_t* addr_length){
	int numbytes;
	struct sockaddr their_addr;
	socklen_t addr_len;
	addr_len = sizeof their_addr;
	if ((numbytes = recvfrom(sockfd, buf, BUFSIZ , 0,
		(struct sockaddr *)&their_addr, &addr_len)) == -1) {
		perror("recvfrom");
		exit(1);
	}
	*addr_length = addr_len;
	return their_addr;
}

/*
Send a udp segment to the sender that just sent us one, using the sockaddr struct returned from a call
to get_udp_packet
Params:
	sockfd: the UDP socket to sent data to 
	buf: the message to send
	their: the sockaddr struct returned from a call to recv 
	addr_len: a socklen_t returned from a call to get_udp_packet()
*/
void send_udp_reply(int sockfd, char* buf, struct sockaddr* their, socklen_t addr_len){
	int numbytes;
	if((numbytes = sendto(sockfd, buf, BUFSIZ, 0, 
						  their, addr_len)) == -1) 
	{
		perror("sending message reply");
		exit(1);
	}
}

/*
Sends a UDP segment to the destination specified in the param their
Params:
	sockfd: the UDP socket to sent data to
	buf: the message to send 
	their: the addrinfo struct that specifies where to send the udp segment 
*/
void send_udp_packet(int sockfd, char* buf, struct addrinfo* their){
	int numbytes;
	if ((numbytes = sendto(sockfd, buf, BUFSIZ, 0,
             their->ai_addr, their->ai_addrlen)) == -1) {
        perror("talker: sendto");
        exit(1);
    }
}