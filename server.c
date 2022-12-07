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
#include "ecdhe.h"
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <unistd.h>

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
	//unsigned char* sign=(unsigned char*)malloc(sizeof(char)*100);
	unsigned char* client_dh = (unsigned char*)malloc(sizeof(char)*800);
	unsigned char* client_pub, *server_pub;
	EC_KEY* server;
	const EC_POINT *server_public;
	int n,f1,digest_len;
	EC_POINT *client_public;
	
	//1. genererate nonce1 which is sent from server to client
	
	f1 = open("/dev/urandom",O_RDONLY);
	read(f1, server_random, sizeof(char)*32);//sizeof(client_random));
	close(f1);
	printf("\nSending server random = %s",server_random);
	
	//recieve random from client
	bzero(buff, sizeof(buff));
	read(connfd, buff, sizeof(buff));
	memcpy(client_random,buff,32);
	printf("\nRecieved Client random : %s", client_random);
	
	//send random to client
	bzero(buff, sizeof(buff));
	memcpy(buff,server_random,32);
	write(connfd, buff, sizeof(buff));
	
	
	//2. Now server sends its public key certificate
	
	//send server public key
	
	f1 = open("Server_keys/public_key.pem",O_RDONLY);	
	read(f1, server_public_key_data, sizeof(char)*2484);	
	close(f1);
	write(connfd, server_public_key_data, sizeof(char)*2484);
	
	//send digital signature
	
	f1 = open("CA_keys/private-key.pem",O_RDONLY);	
	read(f1, ca_private_key_data, sizeof(char)*2484);	
	close(f1);
	digest = signMessage(ca_private_key_data,server_public_key_data);
	write(connfd, digest, 5000);
	//printf("%s",digest);
	
	
	//3. Now recieve the secret from client and send own dh public info ->>>>>>> then derive the premaster secret
	
	//recieve clients public key
	read(connfd, client_dh, 600);
	//printf("\n recieved enc client dh:%s",client_dh);
	bzero(ca_private_key_data, sizeof(ca_private_key_data)); //ca_private_key_data is being reused as server_private_key_data
	f1 = open("Server_keys/private_key.pem",O_RDONLY);	
	read(f1, ca_private_key_data, sizeof(char)*2500);	
	close(f1);
	//printf("%s",ca_private_key_data);
	client_pub = private_decrypt_rsa(ca_private_key_data,client_dh);
	
	printf("\nDecrypted client dh:\n %s",client_pub);
	//convert client_pub back to struct
	client_public = (EC_POINT*)client_pub;
	
	//generate server keys, sign with private key and share with client
	server = create_key();
	server_public = EC_KEY_get0_public_key(server);
	server_pub = (unsigned char*)malloc(sizeof(server_public));
	memcpy(server_pub,(unsigned char*)&server_public, sizeof(server_public));
	//memcpy(server_pub,"1234567",8);
	write(connfd, server_pub, sizeof(server_pub));
	printf("\n sent server dh: %s\n",server_pub);
	
	sleep(5);
	/*
	bzero(digest, 800);
	digest = signMessage(ca_private_key_data,server_pub);
	printf("\n sent digest: %s",digest);
	write(connfd, digest, 600);
	
	printf("\ndecrypted client dh: %s",client_pub);
	printf("\nsent server dh: %s",server_pub);
	//now generate the shared pre-master secret
	/*
	free(server_random);
	free(client_random);
	free(server_public_key_data);
	free(ca_private_key_data);
	free(digest);
	free(client_dh);
	*/
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

