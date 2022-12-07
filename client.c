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
	unsigned char* client_random = (unsigned char*)malloc(sizeof(char)*32);
	unsigned char* server_random = (unsigned char*)malloc(sizeof(char)*32);
	unsigned char* server_public_key_data = (unsigned char*)malloc(sizeof(char)*2500);
	unsigned char* ca_public_key_data = (unsigned char*)malloc(sizeof(char)*2500);
	int n,f1;
	unsigned char* digest = (unsigned char*)malloc(sizeof(char)*600);
	EC_KEY* client;
	const EC_POINT *client_public;
	unsigned char *client_pub, *enc_dh,*server_pub;
	
	
	//1. genererate nonce1 which is sent from client to server
	
	f1 = open("/dev/urandom",O_RDONLY);
	read(f1, client_random, sizeof(char)*32);//sizeof(client_random));
	close(f1);
	printf("\nSending client random = %s",client_random);
	//printf("client nonce = %ld",sizeof(client_random));
	
	//send nonce to server
	bzero(buff, sizeof(buff));
	memcpy(buff,client_random,32);
	write(sockfd, buff, sizeof(buff));
	
	//recieve nonce from server
	bzero(buff, sizeof(buff));
	read(sockfd, buff, sizeof(buff));
	memcpy(server_random,buff,32);
	printf("\nRecieved server random = %s",server_random);
	
	
	//2. Recieve certificate from server and verify it using CA public key
	//recieving public key
	bzero(buff, sizeof(buff));
	read(sockfd, buff, sizeof(buff));
	memcpy(server_public_key_data,buff,2500);
	printf("\nServer public key:\n%s",server_public_key_data);
	//recieving signature
	bzero(buff, sizeof(buff));
	read(sockfd, buff, sizeof(buff));
	memcpy(digest,buff,600);
	printf("\nDigital Signature:\n%s",digest);
	//verifying signature
	f1 = open("CA_keys/public-key.pem",O_RDONLY);	
	read(f1, ca_public_key_data, sizeof(char)*2484);	
	close(f1);
	
	n = verifySignature(ca_public_key_data,server_public_key_data,digest);
	//printf("\nSinature verified: %d",n);
	
	if(n==0){
		printf("Server certificate invalid");
		return;
	}else{
		printf("\nSignature verified\n");
	}
	
	
	//3. Generate pre-master secret by first sending ecdhe parameters to server and recieving response
	
	//generate client ecdhe parameters
	client = create_key();
	client_public = EC_KEY_get0_public_key(client);
	client_pub = (unsigned char*)malloc(sizeof(client_public));
	memcpy(client_pub,(unsigned char*)&client_public, sizeof(client_public));
	
	//encrypt and send using server public rsa key
	enc_dh = public_encrypt_rsa(server_public_key_data,client_pub);
	printf("\nSent Client DH param: %s",client_pub);
	//printf("\nsent to server:%s",enc_dh);
	write(sockfd, enc_dh, 384);
	
	/*
	//TESTING DECRYPTION
	bzero(ca_public_key_data, sizeof(ca_public_key_data)); //ca_private_key_data is being reused as server_private_key_data
	f1 = open("Server_keys/private_key.pem",O_RDONLY);	
	read(f1, ca_public_key_data, sizeof(char)*2500);	
	close(f1);
	//printf("%s",ca_private_key_data);
	client_pub = private_decrypt_rsa(ca_public_key_data,enc_dh);
	printf("\ndecrypted client msg: %s",client_pub);
	*/
	
	//recieve server dh and verify
	sleep(10);
	server_pub = (unsigned char*)malloc(800);
	bzero(buff, sizeof(buff));
	read(sockfd, buff, sizeof(buff));
	memcpy(server_pub,buff,sizeof(server_pub));
	printf("\n Recieved server DH param: %s\n",buff);
	
	
	/*
	bzero(digest, sizeof(digest));
	read(sockfd, digest, 600);
	printf("\n Recieved digital signature:\n %s",digest);
	n = verifySignature(server_public_key_data,server_pub,digest);
	if(n==0){
		printf("\nServer DH tampered: invalid");
		return;
	}
	
	printf("\n client dh: %s",client_pub);
	printf("\nserver dh: %s",server_pub);
	
	free(server_random);
	free(client_random);
	free(server_public_key_data);
	free(ca_public_key_data);
	free(digest);*/
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

