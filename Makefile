CFLAGS := -lcrypto -lssl -lgdbm

CC := gcc

all: ssl-client ssl-server

ssl-client: ssl-client.o
	$(CC)  -o ssl-client ssl-client.o $(CFLAGS)

ssl-client.o: ssl-client.c
	$(CC)  -c ssl-client.c  $(CFLAGS)

ssl-server: ssl-server.o
	$(CC)  -o ssl-server ssl-server.o $(CFLAGS) 

ssl-server.o: ssl-server.c
	$(CC) -c ssl-server.c $(CFLAGS)

clean:
	rm -f ssl-server ssl-server.o ssl-client ssl-client.o
