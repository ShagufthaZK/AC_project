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
#include "aes_gcm.h"
#include <openssl/ec.h>
#include <openssl/ecdh.h>
#include <unistd.h>
#include <openssl/kdf.h>


void func(int sockfd)
{
	char buff[MAX];
	char ciphertext[MAX];
	char tag[30];
	unsigned char master_secret[49];
	unsigned char aes_key[33];
	unsigned char init_iv[12];
	unsigned char* client_random = (unsigned char*)malloc(sizeof(char)*33);
	unsigned char* server_random = (unsigned char*)malloc(sizeof(char)*33);
	unsigned char* seed = (unsigned char*)malloc(sizeof(char)*65);
	unsigned char* server_public_key_data = (unsigned char*)malloc(sizeof(char)*626);
	unsigned char* ca_public_key_data = (unsigned char*)malloc(sizeof(char)*2500);
	int n,f1;
	unsigned char* digest = (unsigned char*)malloc(sizeof(char)*521);
	EC_KEY* client;
	const EC_POINT *client_public, *server_public;
	unsigned char *client_pub, *enc_dh,*server_pub, *pre_master_secret;
	size_t pre_master_secret_len;
	
	
	//1. genererate nonce1 which is sent from client to server
	printf("\n-----------------------------------------------------------------------------\n");
	printf("\n                           SHARING RANDOM NUMBERS                            \n");
	printf("\n-----------------------------------------------------------------------------\n");
	//send nonce to server
	f1 = open("/dev/urandom",O_RDONLY);
	n = read(f1, client_random, sizeof(char)*32);//sizeof(client_random));
	client_random[32]='\0';
	close(f1);
	printf("\nSending client random =\n %s",client_random);
	n = write(sockfd, client_random, 33);
	//printf("\nbytes sent for client random = %d %d",n,sizeof(*client_random));
	
	//recieve nonce from server
	n = read(sockfd, server_random, 33);
	printf("\nRecieved server random = %s",server_random);
	//printf("\nbytes read for server random = %d",n);
	
	
	
	//2. Recieve certificate from server and verify it using CA public key
	printf("\n-----------------------------------------------------------------------------\n");
	printf("\n                    RECIEVING AND VERIFYING SERVER CERTIFICATE               \n");
	printf("\n-----------------------------------------------------------------------------\n");
	//recieving public key
	n = read(sockfd, server_public_key_data, 626);
	printf("\nServer public key:\n%s",server_public_key_data);
	//printf("\nbytes read for Server public key = %d",n);
	
	//recieving signature
	n = read(sockfd, digest, 521);
	printf("\nDigital Signature:\n%s",digest);
	//printf("\nbytes read for digital sign = %d",n);
	
	//verifying signature
	f1 = open("CA_keys/public-key.pem",O_RDONLY);	
	read(f1, ca_public_key_data, sizeof(char)*2484);	
	close(f1);
	n = verifySignature(ca_public_key_data,server_public_key_data,digest);	
	if(n==0){
		printf("\nServer certificate invalid\n");
		return;
	}else{
		printf("\nSignature verified\n");
	}
	
	
	
	//3. Sending ecdhe parameters to server and recieving response
	printf("\n-----------------------------------------------------------------------------\n");
	printf("\n                            EXCHANGING ECDHE PARAMETERS                       \n");
	printf("\n-----------------------------------------------------------------------------\n");
	//generate client ecdhe parameters
	client = create_key();
	client_public = EC_KEY_get0_public_key(client);
	
	//convert param to unsigned char
	client_pub = (unsigned char*)malloc(sizeof(char)*66);
	n = EC_POINT_point2oct(EC_KEY_get0_group(client), client_public, POINT_CONVERSION_UNCOMPRESSED, client_pub, 66, NULL);
	//client_pub[n]='\0';
	//printf("\nlenght of serialized dh param: %d",n);
	
	//encrypt and send using server public rsa key
	enc_dh = public_encrypt_rsa(server_public_key_data,client_pub);
	printf("\nClient DH param:\n%s",client_pub);
	printf("\nSent encrypted dh to server:\n%s",enc_dh);
	n = 0;
	while(enc_dh[n]!='\0') ++n;
	//printf("\nlength of enc_dh:%d",n);
	n = write(sockfd, enc_dh, 600);
	//printf("\nbytes sent to server for dh: %d",n);
	
	//recieve server dh 
	server_pub = (unsigned char*)malloc(66);
	n = read(sockfd, server_pub, 66);
	printf("\nRecieved server DH param:\n%s ",server_pub);
	//server_public = (EC_POINT*)server_pub;
	
	//verify server dh using digital signature
	bzero(digest, 521);
	read(sockfd, digest, 521);
	printf("\nRecieved digital signature:\n %s",digest);
	n = verifySignature(server_public_key_data,server_pub,digest);
	if(n==0){
		printf("\nServer DH tampered: invalid");
		return;
	}else{
		printf("\nServer DH valid");
	}
	
	printf("\n\nclient dh: %s",client_pub);
	printf("\n\nserver dh: %s",server_pub);
	
	
	//4. Generate Pre-master, Master and encryption key
	printf("\n-----------------------------------------------------------------------------\n");
	printf("\n                  GENERATE PRE-MASTER, MASTER AND ENCRYPTION KEYS                \n");
	printf("\n-----------------------------------------------------------------------------\n");
	//generating pre-master key
	server_public = EC_POINT_new(EC_KEY_get0_group(client));
	n = EC_POINT_oct2point(EC_KEY_get0_group(client), server_public, server_pub, 65, NULL);
	//printf("\nconverted into struct point: %d",n);//convert client_pub back to struct
	pre_master_secret = get_secret(client,server_public,&pre_master_secret_len);
	printf("\npre master secret: %s \n ",pre_master_secret);
	
	//generating master key
	memcpy(seed, client_random,32);
	memcpy(seed+32, server_random, 32);
	if(pre_master_secret_len>0){
		EVP_PKEY_CTX *pctx;
		 size_t outlen = sizeof(master_secret);
		 pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);

		 if (EVP_PKEY_derive_init(pctx) <= 0);
		     /* Error */
		 if (EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha3_256()) <= 0);
		     /* Error */
		 if (EVP_PKEY_CTX_set1_hkdf_salt(pctx, seed, 64) <= 0);
		     /* Error */
		 if (EVP_PKEY_CTX_set1_hkdf_key(pctx, pre_master_secret, pre_master_secret_len) <= 0);
		     /* Error */
		 if (EVP_PKEY_CTX_add1_hkdf_info(pctx, "master secret", 13) <= 0);
		     /* Error */
		 if (EVP_PKEY_derive(pctx, master_secret, &outlen) <= 0);
		 printf("\n\nMaster Secret: %s",master_secret);
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
		 printf("\n\naes_key: %s\n",aes_key);
		 printf("\n\ninit_iv: %s",init_iv);
	}
	fflush(stdout);
	//5. Exchange messages encrypted using AES-GCM
	
	printf("\n-----------------------------------------------------------------------------\n");
	printf("\n                  EXCHANGING MESSAGES USING AES256 GCM               \n");
	printf("\n-----------------------------------------------------------------------------\n");
	
	if(pre_master_secret_len>0){
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
		 	//send iv
			bzero(iv, sizeof(iv));
			EVP_PKEY_derive(pctx, iv, &outlen);
			n = write(sockfd, iv, outlen);
			
			fflush(stdout);
			
			//send encrypted mssg
			bzero(buff, sizeof(buff));
			bzero(tag, sizeof(tag));
			bzero(ciphertext, sizeof(ciphertext));
			printf("\nEnter the string (type 'exit' to exit): ");
			n = 0;
			//memcpy(buff,"1234567",7);
			//scanf("%s",buff);
			//while(buff[n++]!='\0');
			while ((buff[n++] = getchar()) != '\n');
			n = gcm_encrypt(buff,n,NULL,0,aes_key,iv,12,ciphertext,tag);
			//if(n>=0)printf("\nencryption successfull");
			//else {printf("\nencryption failed");return;}
			ciphertext[n] = '\0';
			n = write(sockfd, ciphertext, sizeof(ciphertext));
			printf("\niv sent to server:%s",iv);
			printf("\n\nciphertext:%s",ciphertext);
			n = write(sockfd, tag, sizeof(tag));
			printf("\ntag sent: %s",tag);
			//printf("\nmessage sent");
			
			//recieve server iv 
			bzero(iv, sizeof(iv));
			read(sockfd, iv, sizeof(iv));
			
			//decrypt and print server mssg
			bzero(buff, sizeof(buff));
			bzero(ciphertext, sizeof(ciphertext));
			n = read(sockfd, ciphertext, sizeof(ciphertext));
			read(sockfd,tag,sizeof(tag));
			gcm_decrypt(ciphertext,n,NULL,0,tag,aes_key,iv,12,buff);

			printf("\nFrom Server: %s", buff);
			//fflush(stdout);
			
			//end exchange
			if ((strncmp(buff, "exit", 4)) == 0) {
			    printf("\nClient Exit...\n");
			    break;
			}
    		}
	}
		
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

