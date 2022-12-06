#include <arpa/inet.h> // inet_addr()
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h> // bzero()
#include <sys/socket.h>
#include <unistd.h> // read(), write(), close()
#define MAX 3000
#define PORT 8080
#define SA struct sockaddr
#include<fcntl.h>
#include<sys/wait.h>
#include "rsa.h"

void func(int sockfd)
{
	char buff[MAX];
	unsigned char* client_random = (unsigned char*)malloc(sizeof(char)*32);
	unsigned char* server_random = (unsigned char*)malloc(sizeof(char)*32);
	unsigned char* server_public_key_data = (unsigned char*)malloc(sizeof(char)*2500);
	unsigned char* ca_public_key_data = (unsigned char*)malloc(sizeof(char)*2500);
	int n,f1;
	unsigned char* digest = (unsigned char*)malloc(sizeof(char)*600);
	//1. genererate nonce1 which is sent from client to server
	
	f1 = open("/dev/urandom",O_RDONLY);
	read(f1, client_random, sizeof(char)*32);//sizeof(client_random));
	close(f1);
	printf("\nclient nonce = %s",client_random);
	//printf("client nonce = %ld",sizeof(client_random));
	
	//send nonce to server
	bzero(buff, sizeof(buff));
	memcpy(buff,client_random,32);
	write(sockfd, buff, sizeof(buff));
	
	//recieve nonce from server
	bzero(buff, sizeof(buff));
	read(sockfd, buff, sizeof(buff));
	memcpy(server_random,buff,32);
	printf("\nrecieved server random = %s",server_random);
	
	
	//2. Recieve certificate from server and verify it using CA public key
	//recieving public key
	bzero(buff, sizeof(buff));
	read(sockfd, buff, sizeof(buff));
	memcpy(server_public_key_data,buff,2500);
	printf("\n%s",server_public_key_data);
	//recieving signature
	bzero(buff, sizeof(buff));
	read(sockfd, buff, sizeof(buff));
	memcpy(digest,buff,600);
	printf("\n%s",digest);
	//verifying signature
	f1 = open("CA_keys/public-key.pem",O_RDONLY);	
	read(f1, ca_public_key_data, sizeof(char)*2484);	
	close(f1);
	
	n = verifySignature(ca_public_key_data,server_public_key_data,digest);
	printf("\n%d",n);
	
	/*
	for (;;) {
		bzero(buff, sizeof(buff));
		printf("Enter the string : ");
		n = 0;
		while ((buff[n++] = getchar()) != '\n')
			;
		write(sockfd, buff, sizeof(buff));
		bzero(buff, sizeof(buff));
		read(sockfd, buff, sizeof(buff));
		printf("From Server : %s", buff);
		if ((strncmp(buff, "exit", 4)) == 0) {
			printf("Client Exit...\n");
			break;
		}
	}
	*/
	
	
}

int main()
{
	int sockfd, connfd;
	struct sockaddr_in servaddr, cli;

	// socket create and verification
	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (sockfd == -1) {
		printf("socket creation failed...\n");
		exit(0);
	}
	else
		printf("Socket successfully created..\n");
	bzero(&servaddr, sizeof(servaddr));

	// assign IP, PORT
	servaddr.sin_family = AF_INET;
	servaddr.sin_addr.s_addr = inet_addr("127.0.0.1");
	servaddr.sin_port = htons(PORT);

	// connect the client socket to server socket
	if (connect(sockfd, (SA*)&servaddr, sizeof(servaddr))
		!= 0) {
		printf("connection with the server failed...\n");
		exit(0);
	}
	else
		printf("connected to the server..\n");

	// function for chat
	func(sockfd);

	// close the socket
	close(sockfd);
}

