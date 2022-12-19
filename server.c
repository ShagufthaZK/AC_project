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
	unsigned char* client_random = (unsigned char*)malloc(sizeof(char)*33);
	unsigned char* server_public_key_data = (unsigned char*)malloc(sizeof(char)*626);;
	unsigned char* ca_private_key_data = (unsigned char*)malloc(sizeof(char)*2500);
	unsigned char* digest=(unsigned char*)malloc(sizeof(char)*521);
	//unsigned char* sign=(unsigned char*)malloc(sizeof(char)*100);
	unsigned char* client_dh = (unsigned char*)malloc(sizeof(char)*800);
	unsigned char* client_pub, *server_pub;
	EC_KEY* server;
	const EC_POINT *server_public;
	int n,f1,digest_len;
	EC_POINT *client_public;
	
	//1. genererate nonce1 which is sent from server to client
	
	//recieve random from client
	n = read(connfd, client_random, 33);
	printf("\nRecieved Client random : %s", client_random);
	printf("\nbytes read for client random = %d",n);
	
	//send random to client
	f1 = open("/dev/urandom",O_RDONLY);
	read(f1, server_random, sizeof(char)*32);//sizeof(client_random));
	server_random[32]='\0';
	close(f1);
	n = write(connfd, server_random, 33);
	printf("\nSending server random = %s",server_random);
	printf("\nbytes sent for server random = %d",n);
		
		
		
	//2. Now server sends its public key certificate
	
	//send server public key
	f1 = open("Server_keys/public_key.pem",O_RDONLY);	
	n = read(f1, server_public_key_data, 625);
	server_public_key_data[625] = '\0';
	printf("\nbytes in server pk: %d",n);	
	close(f1);
	n = write(connfd, server_public_key_data, 626);
	printf("\nbytes sent in server pk: %d",n);
	
	//send digital signature
	f1 = open("CA_keys/private-key.pem",O_RDONLY);	
	n = read(f1, ca_private_key_data, sizeof(char)*2484);
	//printf("\nbytes in ca pr_k: %d",n);	
	close(f1);
	digest = signMessage(ca_private_key_data,server_public_key_data);
	n = write(connfd, digest, 521);
	n=0;
	while(digest[n]!='\0') ++n;
	printf("digest length :%d",n);
	
	
	
	//3. Now recieve the secret from client and send own dh public info
	
	//recieve enc clients DH public key
	n = read(connfd, client_dh, 384);
	printf("\n bytes sent to server for dh: %d",n);
	//printf("\n recieved enc client dh:%s",client_dh);
	
	//decrypt the recieved params
	bzero(ca_private_key_data, sizeof(ca_private_key_data)); //ca_private_key_data is being reused as server_private_key_data
	f1 = open("Server_keys/private_key.pem",O_RDONLY);	
	read(f1, ca_private_key_data, sizeof(char)*2500);	
	close(f1);
	client_pub = private_decrypt_rsa(ca_private_key_data,client_dh);
	printf("\nDecrypted client dh:\n %s",client_pub);
	client_public = (EC_POINT*)client_pub; //convert client_pub back to struct
	
	//generate server keys, sign with private key and share with client
	server = create_key();
	server_public = EC_KEY_get0_public_key(server);
	server_pub = (unsigned char*)malloc(sizeof(server_public));
	memcpy(server_pub,(unsigned char*)&server_public, sizeof(server_public));
	n = write(connfd, server_pub, sizeof(server_pub));
	printf("\n sent server dh: %s and bytes written %d\n",server_pub,n);
	
	//send the digital signature for server DH param
	
	bzero(digest, 521);
	digest = signMessage(ca_private_key_data,server_pub);
	printf("\n sent digest: %s",digest);
	write(connfd, digest, 521);
	
	printf("\ndecrypted client dh: %s",client_pub);
	printf("\nsent server dh: %s",server_pub);
	
	
	
	//4. Generate Pre-master, Master and encryption key
	
	//generating pre-master key
	
	//generating master key
	
	//generating encryption key
	
	free(server_random);
	free(client_random);
	free(server_public_key_data);
	free(ca_private_key_data);
	free(digest);
	free(client_dh);
	
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

