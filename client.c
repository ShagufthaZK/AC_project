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
#include "ecdhe.h"
#include <openssl/ec.h>
#include <openssl/ecdh.h>
#include <unistd.h>

void func(int sockfd)
{
	char buff[MAX];
	unsigned char* client_random = (unsigned char*)malloc(sizeof(char)*33);
	unsigned char* server_random = (unsigned char*)malloc(sizeof(char)*33);
	unsigned char* server_public_key_data = (unsigned char*)malloc(sizeof(char)*626);
	unsigned char* ca_public_key_data = (unsigned char*)malloc(sizeof(char)*2500);
	int n,f1;
	unsigned char* digest = (unsigned char*)malloc(sizeof(char)*521);
	EC_KEY* client;
	const EC_POINT *client_public;
	unsigned char *client_pub, *enc_dh,*server_pub;
	
	
	//1. genererate nonce1 which is sent from client to server
	
	//send nonce to server
	f1 = open("/dev/urandom",O_RDONLY);
	n = read(f1, client_random, sizeof(char)*32);//sizeof(client_random));
	client_random[32]='\0';
	close(f1);
	printf("\nSending client random =\n %s",client_random);
	n = write(sockfd, client_random, 33);
	printf("\nbytes sent for client random = %d %d",n,sizeof(*client_random));
	
	//recieve nonce from server
	n = read(sockfd, server_random, 33);
	printf("\nRecieved server random = %s",server_random);
	printf("\nbytes read for server random = %d",n);
	
	
	
	//2. Recieve certificate from server and verify it using CA public key
	
	//recieving public key
	n = read(sockfd, server_public_key_data, 626);
	printf("\nServer public key:\n%s",server_public_key_data);
	printf("\nbytes read for Server public key = %d",n);
	
	//recieving signature
	n = read(sockfd, digest, 521);
	printf("\nDigital Signature:\n%s",digest);
	printf("\nbytes read for digital sign = %d",n);
	
	//verifying signature
	f1 = open("CA_keys/public-key.pem",O_RDONLY);	
	read(f1, ca_public_key_data, sizeof(char)*2484);	
	close(f1);
	n = verifySignature(ca_public_key_data,server_public_key_data,digest);	
	if(n==0){
		printf("Server certificate invalid");
		return;
	}else{
		printf("\nSignature verified\n");
	}
	
	
	
	//3. Sending ecdhe parameters to server and recieving response
	
	//generate client ecdhe parameters
	client = create_key();
	client_public = EC_KEY_get0_public_key(client);
	client_pub = (unsigned char*)malloc(sizeof(client_public));
	memcpy(client_pub,(unsigned char*)&client_public, sizeof(client_public));
	
	//encrypt and send using server public rsa key
	enc_dh = public_encrypt_rsa(server_public_key_data,client_pub);
	printf("\nSent Client DH param: %s",client_pub);
	//printf("\nsent to server:%s",enc_dh);
	n = write(sockfd, enc_dh, 384);
	printf("\n bytes sent to server for dh: %d",n);
	
	//recieve server dh 
	server_pub = (unsigned char*)malloc(800);
	bzero(buff, sizeof(buff));
	n = read(sockfd, buff, sizeof(buff));
	memcpy(server_pub,buff,sizeof(server_pub));
	printf("\n Recieved server DH param: %s and bytes read %d\n",buff,n);
	
	
	//verify server dh using digital signature
	bzero(digest, 521);
	read(sockfd, digest, 521);
	printf("\n Recieved digital signature:\n %s",digest);
	n = verifySignature(server_public_key_data,server_pub,digest);
	if(n==0){
		printf("\nServer DH tampered: invalid");
		return;
	}else{
		printf("\nServer DH valid");
	}
	
	printf("\n client dh: %s",client_pub);
	printf("\nserver dh: %s",server_pub);
	
	
	//4. Generate Pre-master, Master and encryption key
	
	//generating pre-master key
	
	//generating master key
	
	//generating encryption key
	
	free(server_random);
	free(client_random);
	free(server_public_key_data);
	free(ca_public_key_data);
	free(digest);
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

