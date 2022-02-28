#ifndef NETWORK_H
#define NETWORK_H

#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>

/*
TCP Server Side Functions
*/
void sigchld_handler(int s);
void *get_in_addr(struct sockaddr *sa);
int get_server_tcp_socket(char* port);
void set_reap_handler();
void listen_on_sock(int sockfd, int backlog_count);
int get_connection_socket(int sockfd);

/*
TCP Client Side Functions
*/
int get_client_tcp_socket(char* port, char* nodename);

/*
UDP Functions
*/
int get_server_udp_socket(const char* port, struct addrinfo* info);
struct sockaddr get_udp_packet(int sockfd, char* buf, socklen_t* addr_length);
int get_client_udp_socket(const char* port, const char* hostname, struct addrinfo* info);
void send_udp_reply(int sockfd, char* buf, struct sockaddr* their, socklen_t addr_len);
void send_udp_packet(int sockfd, char* buf, struct addrinfo* their);

#endif //NETWORK_H