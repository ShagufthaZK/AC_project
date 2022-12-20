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
#include "aes_gcm.h"
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <unistd.h>
#include <openssl/ec.h>
#include <openssl/ecdh.h>
#include <openssl/evp.h>

// Function designed for chat between client and server.

#define HANDLE_ERROR(msg) { fprintf(stderr, "%s\n", msg); exit(EXIT_FAILURE); }
#define HANDLE_ERROR2(msg, mdctx) { fprintf(stderr, "%s\n", msg); EVP_MD_CTX_destroy(mdctx); exit(EXIT_FAILURE); }

void func(int connfd)
{
	char buff[MAX];
	char ciphertext[MAX];
	char tag[30];
	unsigned char master_secret[49];
	unsigned char aes_key[33];
	unsigned char init_iv[12];
	unsigned char* server_random = (unsigned char*)malloc(sizeof(char)*33);
	unsigned char* client_random = (unsigned char*)malloc(sizeof(char)*33);
	unsigned char* seed = (unsigned char*)malloc(sizeof(char)*65);
	unsigned char* server_public_key_data = (unsigned char*)malloc(sizeof(char)*626);;
	unsigned char* ca_private_key_data = (unsigned char*)malloc(sizeof(char)*2500);
	unsigned char* digest=(unsigned char*)malloc(sizeof(char)*521);
	unsigned char* client_dh = (unsigned char*)malloc(sizeof(char)*600);
	unsigned char* client_pub, *server_pub, *pre_master_secret;
	EC_KEY *server;
	const EC_POINT *server_public;
	EC_POINT *client_public;
	int n,f1,digest_len;
	size_t pre_master_secret_len;
	
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
	n = read(connfd, client_dh, 600);
	printf("\n bytes sent to server for dh: %d",n);
	printf("\n recieved enc client dh:%s",client_dh);
	
	//decrypt the recieved params
	bzero(ca_private_key_data, 2500); //ca_private_key_data is being reused as server_private_key_data
	f1 = open("Server_keys/private_key.pem",O_RDONLY);	
	read(f1, ca_private_key_data, sizeof(char)*2500);	
	close(f1);
	client_pub = private_decrypt_rsa(ca_private_key_data,client_dh);
	printf("\nDecrypted client dh:\n %s",client_pub);
	
	
	//generate server keys, sign with private key and share with client
	server = create_key();
	server_public = EC_KEY_get0_public_key(server);
	printf("\n sent server dh: %s ",server_public);
	server_pub = (unsigned char*)malloc(sizeof(char)*66);
	n = EC_POINT_point2oct(EC_KEY_get0_group(server), server_public, POINT_CONVERSION_UNCOMPRESSED, server_pub, 66, NULL);
	server_pub[n]='\0';
	printf("\nlenght of serialized dh param: %d",n);
	n = write(connfd, server_pub, 66);
	printf("\n sent server dh: %s and bytes written %d\n",server_pub,n);
	
	//send the digital signature for server DH param
	
	bzero(digest, 521);
	digest = signMessage(ca_private_key_data,server_pub);
	printf("\nsent digest: %s",digest);
	write(connfd, digest, 521);
	
	printf("\ndecrypted client dh: %s",client_pub);
	printf("\nsent server dh: %s",server_pub);
	
	
	
	//4. Generate Pre-master, Master and encryption key
	
	//generating pre-master key
	client_public = EC_POINT_new(EC_KEY_get0_group(server));
	printf("\nconverted into struct point: %d",EC_POINT_oct2point(EC_KEY_get0_group(server), client_public, client_pub, 65, NULL));//convert client_pub back to struct
	pre_master_secret = get_secret(server,client_public,&pre_master_secret_len);
	printf("\npre master secret: %s \n %d",pre_master_secret,pre_master_secret_len);
	
	
	//generating master key
	memcpy(seed, client_random,32);
	memcpy(seed+32, server_random, 32);
	if(pre_master_secret_len>0){
		EVP_PKEY_CTX *pctx;
		 size_t outlen = sizeof(master_secret);
		 pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);

		 if (EVP_PKEY_derive_init(pctx) <= 0);
		     
		 if (EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha3_256()) <= 0);
		     
		 if (EVP_PKEY_CTX_set1_hkdf_salt(pctx, seed, 64) <= 0);
		     
		 if (EVP_PKEY_CTX_set1_hkdf_key(pctx, pre_master_secret, pre_master_secret_len) <= 0);
		     
		 if (EVP_PKEY_CTX_add1_hkdf_info(pctx, "master secret", 13) <= 0);
		     /* Error */
		 if (EVP_PKEY_derive(pctx, master_secret, &outlen) <= 0);
		 printf("\nMaster Secret: %s",master_secret);
	}
	
	//generating encryption key
	if(pre_master_secret_len>0){
		EVP_PKEY_CTX *pctx;
		 size_t outlen = sizeof(aes_key);
		 pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);

		 if (EVP_PKEY_derive_init(pctx) <= 0);
		     /* Error */
		 if (EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha3_256()) <= 0);
		     /* Error */
		 if (EVP_PKEY_CTX_set1_hkdf_salt(pctx, seed, 64) <= 0);
		     /* Error */
		 if (EVP_PKEY_CTX_set1_hkdf_key(pctx, master_secret, 48) <= 0);
		     /* Error */
		 if (EVP_PKEY_CTX_add1_hkdf_info(pctx, "key expansion", 13) <= 0);
		     /* Error */
		 if (EVP_PKEY_derive(pctx, aes_key, &outlen) <= 0);
		 outlen = sizeof(init_iv);
		 if (EVP_PKEY_derive(pctx, init_iv, &outlen) <= 0);
		 if (EVP_PKEY_derive(pctx, init_iv, &outlen) <= 0);//so that server and client init_iv's are different
		 printf("\naes_key: %s",aes_key);
		 printf("\ninit_iv: %s",init_iv);
	}
	fflush(stdout);
	
	//5. Exchange messages encrypted using AES-GCM
	if(1>0){
		EVP_PKEY_CTX *pctx;
		unsigned char iv[12];
		 size_t outlen = sizeof(iv);
		 pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);

		 if (EVP_PKEY_derive_init(pctx) <= 0);
		     
		 if (EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha3_256()) <= 0);
		     
		 if (EVP_PKEY_CTX_set1_hkdf_salt(pctx, seed, 64) <= 0);
		     
		 if (EVP_PKEY_CTX_set1_hkdf_key(pctx, init_iv, 12) <= 0);
		     
		 if (EVP_PKEY_CTX_add1_hkdf_info(pctx, "iv expansion", 12) <= 0);
		     
		for (;;) {
		
			//recieve iv
			bzero(iv, sizeof(iv));
			n = read(connfd, iv, 12);
			printf("\nbytes of iv recieved: %d %s",n,iv);
			fflush(stdout);
			
			//recieve enc mssg and tag
			bzero(ciphertext, sizeof(ciphertext));
			n = read(connfd, ciphertext, sizeof(ciphertext));
			printf("\nbytes of ciphertext recieved: %d \nciphertext:%s",n,ciphertext);
			n = read(connfd,tag,sizeof(tag));
			printf("\nbytes of tag recieved: %d %s",n,tag);
			
			//decrypt and print mssg
			n = gcm_decrypt(ciphertext,n,NULL,0,tag,aes_key,iv,12,buff);
			if(n>=0)printf("\ndecryption successfull");
			//else {printf("\ndecryption failed");return;}
			printf("\nFrom client: %s\t To client : ", buff);
			fflush(stdout);
			
			//send own iv
			bzero(iv, sizeof(iv));
			EVP_PKEY_derive(pctx, iv, &outlen);
			write(connfd, iv, sizeof(iv));
			
			//send own enc mssg and tag
			bzero(buff, MAX);
			n = 0;
			//memcpy(buff,"abcdefg",7);
			//while (buff[n++] != '\0');
			while ((buff[n++] = getchar()) != '\n');
			gcm_encrypt(buff,n,NULL,0,aes_key,iv,12,ciphertext,tag);
			write(connfd, ciphertext, sizeof(ciphertext));
			write(connfd, tag, sizeof(tag));
			
			if (strncmp("exit", buff, 4) == 0) {
			    printf("\nServer Exit...\n");
			    break;
			}
	    	}
    	}
	
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

