#include <stdio.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h> // read(), write(), close()
#define MAX 3000
#define PORT 8080
#define SA struct sockaddr
#include<fcntl.h>
#include<sys/wait.h>
#include "rsa.h"
#include <openssl/sha.h>


#include <openssl/evp.h>

// Function designed for chat between client and server.

#define HANDLE_ERROR(msg) { fprintf(stderr, "%s\n", msg); exit(EXIT_FAILURE); }
#define HANDLE_ERROR2(msg, mdctx) { fprintf(stderr, "%s\n", msg); EVP_MD_CTX_destroy(mdctx); exit(EXIT_FAILURE); }

void func(int connfd)
{
	char buff[MAX];
	
	unsigned char* server_random = (unsigned char*)malloc(sizeof(char)*32);
	unsigned char* client_random = (unsigned char*)malloc(sizeof(char)*32);
	unsigned char* server_public_key_data = (unsigned char*)malloc(sizeof(char)*2500);;
	unsigned char* ca_private_key_data = (unsigned char*)malloc(sizeof(char)*2500);
	unsigned char* digest=(unsigned char*)malloc(sizeof(char)*800);
	unsigned char* sign=(unsigned char*)malloc(sizeof(char)*100);
	int n,f1,digest_len;
	EVP_MD_CTX * mdctx;
	EVP_MD * algo = EVP_sha3_512();
	//FILE* fp;
	
	//1. genererate nonce1 which is sent from server to client
	
	f1 = open("/dev/urandom",O_RDONLY);
	read(f1, server_random, sizeof(char)*32);//sizeof(client_random));
	close(f1);
	//printf("server nonce = %s",server_random);
	
	//recieve random from client
	bzero(buff, sizeof(buff));
	read(connfd, buff, sizeof(buff));
	memcpy(client_random,buff,32);
	//printf("Recieved Client nonce : %s", client_random);
	
	//send random to client
	bzero(buff, sizeof(buff));
	memcpy(buff,server_random,32);
	write(connfd, buff, sizeof(buff));
	
	
	//2. Now server sends its public key certificate
	
	//send server public key
	
	f1 = open("Server_keys/private_key.pem",O_RDONLY);	
	read(f1, server_public_key_data, sizeof(char)*2484);	
	close(f1);
	write(connfd, server_public_key_data, sizeof(char)*2484);
	
	//send digital signature
	/*
	if ((mdctx = EVP_MD_CTX_create()) == NULL) {
		HANDLE_ERROR("EVP_MD_CTX_create() error")
	}
	if (EVP_DigestInit_ex(mdctx, algo, NULL) != 1) { // returns 1 if successful
		HANDLE_ERROR2("EVP_DigestInit_ex() error", mdctx)
	}
	
	if (EVP_DigestUpdate(mdctx, server_public_key_data, 2484) != 1) { // returns 1 if successful
			HANDLE_ERROR2("EVP_DigestUpdate() error", mdctx)
	}
	
	digest_len = EVP_MD_size(algo);

	if ((digest = (unsigned char *)OPENSSL_malloc(digest_len)) == NULL) {
		HANDLE_ERROR2("OPENSSL_malloc() error", mdctx)
	}

	// produce digest
	if (EVP_DigestFinal_ex(mdctx, digest, &digest_len) != 1) { // returns 1 if successful
		OPENSSL_free(digest);
		HANDLE_ERROR2("EVP_DigestFinal_ex() error", mdctx)
	}
	private_encrypt(digest,64,"CA_keys/private-key.pem",sign);
	write(connfd, sign, digest_len+10);
	
	/*
	openssl_evp_rsa_signature(server_public_key_data,2484,digest,64,"CA_keys/private-key.pem",NULL);
	printf("\n%s",digest);
	*/
	//printf("\n%s \n hi",sign);
	
	//write(connfd, digest, digest_len+10);	
	f1 = open("CA_keys/private-key.pem",O_RDONLY);	
	read(f1, ca_private_key_data, sizeof(char)*2484);	
	close(f1);
	digest = signMessage(ca_private_key_data,server_public_key_data);
	write(connfd, digest, 5000);
	printf("%s",digest);
	free(server_random);
	free(client_random);
	free(server_public_key_data);
	free(ca_private_key_data);
	free(digest);
	
}

// Driver function
int main()
{
	int sockfd, connfd, len;
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
	servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
	servaddr.sin_port = htons(PORT);

	// Binding newly created socket to given IP and verification
	if ((bind(sockfd, (SA*)&servaddr, sizeof(servaddr))) != 0) {
		printf("socket bind failed...\n");
		exit(0);
	}
	else
		printf("Socket successfully binded..\n");

	// Now server is ready to listen and verification
	if ((listen(sockfd, 5)) != 0) {
		printf("Listen failed...\n");
		exit(0);
	}
	else
		printf("Server listening..\n");
	len = sizeof(cli);

	// Accept the data packet from client and verification
	connfd = accept(sockfd, (SA*)&cli, &len);
	if (connfd < 0) {
		printf("server accept failed...\n");
		exit(0);
	}
	else
		printf("server accept the client...\n");

	// Function for chatting between client and server
	func(connfd);

	// After chatting close the socket
	close(sockfd);
}

