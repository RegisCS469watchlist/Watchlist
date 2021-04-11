CC := gcc

all: client server

client: client.o
	$(CC) -o client client.o 

client.o: client.c
	$(CC) -c client.c

server: server.o
	$(CC) -o server server.o -lgdbm

server.o: server.c
	$(CC) -c server.c -lgdbm

clean:
	rm -f server server.o client client.o
