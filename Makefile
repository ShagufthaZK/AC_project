all:
	gcc server.c -o server -lcrypto
	gcc client.c -o client -lcrypto
