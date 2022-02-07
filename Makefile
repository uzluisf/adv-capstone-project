CC      = gcc
CFLAGS  = -g
RM      = rm -f


default: all

all: client server

client: client.c
	$(CC) $(CFLAGS) -o client client.c

server: server.c
	$(CC) $(CFLAGS) -o server server.c


clean:
	rm -f client server
