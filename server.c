/******************************************************************************
Title       : server.c
Author      : Luis Filion
Course      : CS499 - Advanced Capstone (Hunter College)
Professor   : Soumik Dey
Created on  : Sept. 22, 2021
Name        : Single-server Multi-client Using C Sockets
Description : Single-server multi-client implementation using C sockets. To
              establish a connection between server and clients, a three-way
              mechanism is used whereby the client sends a SYN packet to the server,
              the server responds with a SYN-ACK packet, and finally the client
              responds with an ACK packet at which point a connection has been
              established, and data can be exchanged.

              After the handshake, whenever a client sends a message to the
              server the message is sent back to the client. To ensure the
              message hasn't been corrupted, a few cases are handled most
              notably whether or not data was sent back the server, and if
              the data is integral (i.e., does its server-computed hash matches
              the one computed by the client?). In the cases where either of these
              cases fails, the client asks for retransmission, the server retransmits
              the data 3 times. If the number of retransmission attempts is exceeded,
              then the server closes the connection with the client.

              If all the checks pass, then the client has received the right
              and untampered data .

Purpose     : Demonstrates how to implement a three-way handshake to
              establish a connection between client and a server.
Usage       : ./server
Build with  : gcc server.c -o server
Modified    : September 24-27, 2021
                Implemented 3-way handshake. 
              October 15, 2021 
                Implemented the data exchange.
              October 30, 2021 
                Handle edge cases for the data exchange.
              November 15, 2021
                Implement multi-client using fork().
              December 3, 2021
                Replace fork() with select().
              December 17, 2021
                Clean-up code and add documentation.
******************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <time.h>
#include <ctype.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/time.h>
#include <netdb.h>

#define PORT 8888
#define BACKLOG 100
#define SERVER_ISN 2001
#define SHAKESIZE 256
#define MAX_RETRANSM 3
#define DATASIZE 1024
#define VERBOSE_PRINT 1

struct capshdr {
    uint8_t  version;  // protocol's version

    uint16_t ack;      // acknowledgement
    uint16_t syn;      // synchronization
    uint16_t seq;      // ISN (Initial Sequence Number)
    uint16_t bufsize;  // agreed-upon buffer size

    uint16_t checksum; // data's checksum
    uint16_t len;      // data's length
};

uint16_t ichecksum(uint16_t *addr, int len);
void pack_uint16_t(char *buffer, uint16_t value);
uint16_t unpack_uint16_t(char *buffer);
void pack_uint8_t(char *buffer, uint8_t value);
uint16_t unpack_uint8_t(char *buffer);

void serialize_header(char *buffer, struct capshdr header);
void deserialize_header(char *buffer, struct capshdr *header);

void delay(unsigned int secs);
void print_header(struct capshdr header);

int check(int exp, const char *msg);
int setup_server(short port, int backlog);

int main(int argc , char *argv[]) {
	int master_socket;
    int addrlen;
    int acceptdf;
    int client_socket[30];
	int max_clients = 30;
	int max_sd;
	struct sockaddr_in address;

    // set of socket descriptors and initialise all client_socket[] to 0 so not checked.
	fd_set ready_sockets;
	for (int i = 0; i < max_clients; i++) {
	    client_socket[i] = 0;
	}

    printf("+-------------------------------------------------------+\n");
    printf("|                        SERVER                         |\n");
    printf("+-------------------------------------------------------+\n\n");

    master_socket = setup_server(PORT, BACKLOG);
	addrlen = sizeof(address);

	printf("*** waiting for connections ***\n");

    char *hbuffer = malloc(SHAKESIZE * sizeof(char));
    char *hmsg = malloc(SHAKESIZE * sizeof(char));
    struct capshdr shandshake;

	while (true) {
		// clear the socket set
		FD_ZERO(&ready_sockets);

		// add master socket to set
		FD_SET(master_socket, &ready_sockets);
		max_sd = master_socket;

		// add child sockets to set
		for (int i = 0 ; i < max_clients ; i++) {
			// socket descriptor
			int sd = client_socket[i];

			//if it's a valid socket descriptor, then add to socket set.
			if (sd > 0) {
			    FD_SET(sd, &ready_sockets);
            }

			// highest file descriptor number
			if (sd > max_sd) {
			    max_sd = sd;
            }
		}

		// wait for an activity on one of the sockets, timeout is NULL ,
		int selectres = select(max_sd + 1, &ready_sockets, NULL, NULL, NULL);
		if ((selectres < 0) && (errno != EINTR)) {
            check(selectres, "select() failed");
		}

		// if something happened on the master socket, then its an incoming connection
		if (FD_ISSET(master_socket, &ready_sockets)) {
			int acceptdf = accept(master_socket, (struct sockaddr *)&address, (socklen_t*)&addrlen);
            if (acceptdf < 0) {
				perror("accept");
				exit(EXIT_FAILURE);
			}

            printf("\n");

///////////////////////////////////////////////////////////////////////////
// END: 3-WAY HANDSHAKE
///////////////////////////////////////////////////////////////////////////

            ///////////////////////////////////////////////////////////////////////////
            // SYN: FIRST HANDSHAKE
            ///////////////////////////////////////////////////////////////////////////

            // server receives the SYN packet.
            read(acceptdf, hbuffer, SHAKESIZE);
            deserialize_header(hbuffer, &shandshake);

            unsigned syn_status = shandshake.syn;
            if (syn_status == 1) {
                // send SYN status to client.
                memset(hmsg, 0, SHAKESIZE);
                sprintf(hmsg, "%d", 1);
                write(acceptdf, hmsg, SHAKESIZE);
                printf("1) SYN received.\n");
                // continue with SYN-ACK.
            }
            else {
                // send SYN status to client.
                memset(hmsg, 0, SHAKESIZE);
                sprintf(hmsg, "%d", 0);
                write(acceptdf, hmsg, SHAKESIZE);

                for (;;) {
                    // receive SYN packet from client.
                    memset(hbuffer, 0, SHAKESIZE);
                    int read_bytes = read(acceptdf, hbuffer, SHAKESIZE);

                    if (read_bytes == 0) {
                        printf("Error: server didn't receive SYN. Connection closed.\n");
                        close(master_socket);
                        exit(0);
                    }

                    deserialize_header(hbuffer, &shandshake);

                    // let client knows status of SYN
                    syn_status = shandshake.syn;
                    if (syn_status == 1) {
                        memset(hmsg, 0, SHAKESIZE);
                        sprintf(hmsg, "%d", 1);
                        write(acceptdf, hmsg, SHAKESIZE);
                        printf("1) SYN received.\n");

                        // continue with SYN-ACK.
                        break;
                    }
                    else {
                        memset(hmsg, 0, SHAKESIZE);
                        sprintf(hmsg, "%d", 0);
                        write(acceptdf, hmsg, SHAKESIZE);
                    }
                }
            }

            ///////////////////////////////////////////////////////////////////////////
            // SYN-ACK: SECOND HANDSHAKE
            ///////////////////////////////////////////////////////////////////////////

            shandshake.ack = shandshake.seq + 1; // ACK = client's ISN + 1
            shandshake.syn = 1;                  // server signals connection request to client
            shandshake.seq = SERVER_ISN;         // server's own ISN

            memset(hbuffer, 0, SHAKESIZE);
            serialize_header(hbuffer, shandshake);
            write(acceptdf, hbuffer, SHAKESIZE);

            // receive to receiver SYN-ACK status from client.
            unsigned int synack_status = 1;
            memset(hmsg, 0, SHAKESIZE);
            read(acceptdf, hmsg, SHAKESIZE);
            sscanf(hmsg, "%d", &synack_status);

            if (synack_status == 1) {
                printf("2) SYN-ACK sent.\n");
                // continue with ACK.
            }
            else {
                int trials;
                for (trials = 1; trials <= MAX_RETRANSM; trials++) {
                    // send SYN-ACK to client.
                    memset(hbuffer, 0, SHAKESIZE);
                    serialize_header(hbuffer, shandshake);
                    write(acceptdf, hbuffer, SHAKESIZE);

                    // receive SYN-ACK status from client.
                    memset(hmsg, 0, SHAKESIZE);
                    read(acceptdf, hmsg, SHAKESIZE);
                    sscanf(hmsg, "%d", &synack_status);

                    if (synack_status == 1) {
                        printf("2) SYN-ACK sent.\n");
                        break;
                        // continue with ACK
                    }
                    else {
                        delay(5);
                    }
                }

                // number of retransmissions exceeded thus close connection with client.
                if (trials > MAX_RETRANSM) {
                    printf("Error: server exceeded retransmission attempts of SYN-ACK packet. Connection closed.\n");
                    close(master_socket);
                    exit(0);
                }
            }

            ///////////////////////////////////////////////////////////////////////////
            // ACK: THIRD HANDSHAKE
            ///////////////////////////////////////////////////////////////////////////

            memset(hbuffer, 0, SHAKESIZE);
            read(acceptdf, hbuffer, SHAKESIZE);
            deserialize_header(hbuffer, &shandshake);

            shandshake.ack -= 1;
            unsigned int ack_status = (shandshake.ack == (SERVER_ISN + 1));

            if (ack_status == 1) {
                // send ACK status to client.
                memset(hmsg, 0, SHAKESIZE);
                sprintf(hmsg, "%d", 1);
                write(acceptdf, hmsg, SHAKESIZE);
                printf("3) ACK received.\n");
                // handshake finished.
            }
            else {
                // send ACK status to client.
                memset(hmsg, 0, SHAKESIZE);
                sprintf(hmsg, "%d", 0);
                write(acceptdf, hmsg, SHAKESIZE);

                for (;;) {
                    // receive ACK packet from client.
                    memset(hbuffer, 0, SHAKESIZE);
                    int read_bytes = read(acceptdf, hbuffer, SHAKESIZE);

                    if (read_bytes == 0) {
                        printf("Error: client didn't send ACK packet. Connection closed.\n");
                        close(master_socket);
                        exit(0);
                    }

                    deserialize_header(hbuffer, &shandshake);

                    ack_status = (shandshake.ack == (SERVER_ISN + 1));
                    if (ack_status == 1) {
                        memset(hmsg, 0, SHAKESIZE);
                        sprintf(hmsg, "%d", 1);
                        write(acceptdf, hmsg, SHAKESIZE);
                        printf("3) ACK received.\n");

                        // continue...
                        break;
                    }
                    else {
                        memset(hmsg, 0, SHAKESIZE);
                        sprintf(hmsg, "%d", 0);
                        write(acceptdf, hmsg, SHAKESIZE);
                    }
                }
            }

            // printf("\n");

///////////////////////////////////////////////////////////////////////////
// END: 3-WAY HANDSHAKE
///////////////////////////////////////////////////////////////////////////

			// inform user of socket number - used in send and receive commands
            // printf("client on port %d (IP: %s) connected successfully.",
            //     ntohs(address.sin_port),
            //     inet_ntoa(address.sin_addr)
            // );

			printf("client on port %d (IP %s) connected.\n",
                ntohs(address.sin_port),
                inet_ntoa(address.sin_addr)
            );
            printf("\n");

			// add new socket to array of sockets
			for (int i = 0; i < max_clients; i++) {
				// if position is empty
				if (client_socket[i] == 0) {
					client_socket[i] = acceptdf;
					break;
				}
			}
		}
        else {
            // loop through the collection and figures out which has incoming connection
		    for (int i = 0; i < max_clients; i++) {
		    	int acceptdf = client_socket[i];

		    	if (FD_ISSET(acceptdf, &ready_sockets)) {

                    int bufsize = shandshake.bufsize;
                    char *buffer = malloc(bufsize * sizeof(char));

                    int valread = read(acceptdf, buffer, shandshake.bufsize);

		    		if (valread == 0) {
		    			getpeername(acceptdf, (struct sockaddr*)&address, (socklen_t*)&addrlen);

                        printf("client on port %d (IP %s) disconnected.\n",
                            ntohs(address.sin_port),
                            inet_ntoa(address.sin_addr)
                        );
                        printf("\n");

                        // close the socket and mark its slot for reuse.
		    			close(acceptdf);
		    			client_socket[i] = 0;
		    		}
		    		else {
                        // allocate memory for the data.
                        char *payload = malloc(DATASIZE * sizeof(char));
                        strcpy(payload, buffer);

                        struct capshdr header;
                        header.version  = 1;
                        header.ack      = 0;
                        header.syn      = 0;
                        header.seq      = 0;
                        header.checksum = ichecksum((uint16_t*)payload, strlen(payload));
                        header.len      = strlen(payload);
                        header.bufsize  = shandshake.bufsize;

                        // serialize header and data into buffer.
                        serialize_header(buffer, header);
                        memcpy(&buffer[13], payload, header.len);
                        // send payload (header + data) to client.
                        write(acceptdf, buffer, bufsize);

                        ///////////////////////////////////////////////////////////////////////////
                        // START: CHECK THAT CLIENT RECEIVES DATA.
                        ///////////////////////////////////////////////////////////////////////////

                        char *pmsg = malloc(SHAKESIZE * sizeof(char));
                        unsigned int payload_status = 1;

                        memset(pmsg, 0, SHAKESIZE);
                        read(acceptdf, pmsg, SHAKESIZE);
                        sscanf(pmsg, "%d", &payload_status);

                        if (payload_status == 1) {
		    			    getpeername(acceptdf, (struct sockaddr*)&address, (socklen_t*)&addrlen);
                            printf("client on port %d received payload.\n", ntohs(address.sin_port));
                        }
                        else {
                            int trials;
                            for (trials = 1; trials <= MAX_RETRANSM; trials++) {
                                memset(buffer, 0, bufsize);
                                serialize_header(buffer, header);
                                memcpy(&buffer[13], payload, header.len);
                                write(acceptdf, buffer, bufsize);

                                if (VERBOSE_PRINT) {
                                    printf("server is sending header + payload to client.\n");
                                    printf("\t");
                                    print_header(header);
                                    printf("\t");
                                    printf("payload: %s\n", payload);
                                    printf("\n");
                                }

                                memset(pmsg, 0, SHAKESIZE);
                                read(acceptdf, pmsg, SHAKESIZE);
                                sscanf(pmsg, "%d", &payload_status);

                                if (payload_status == 1) {
                                    getpeername(acceptdf, (struct sockaddr*)&address, (socklen_t*)&addrlen);
                                    printf("client on port %d received payload.\n", ntohs(address.sin_port));
                                    break;
                                }
                                else {
                                    delay(5);
                                }
                            }

                            if (trials > MAX_RETRANSM) {
                                printf("Error: server exceeded retransmission of payload. Connection closed.\n");
                                close(acceptdf);
                                exit(0);
                            }
                        }

                        ///////////////////////////////////////////////////////////////////////////
                        // END: CHECK THAT CLIENT RECEIVES DATA.
                        ///////////////////////////////////////////////////////////////////////////

                        //////////////////////////////////////////////////////////////////////////////
                        // START: CHECK THE PAYLOAD'S INTEGRITY.
                        //////////////////////////////////////////////////////////////////////////////

                        // Prepare server to receive a packet from the client. It could be
                        // either
                        //
                        // 1) an acknowledgement (ACK) in which case the client acknowleges it
                        // received the correct data. An ACK is simply the sent checksum + 1, which
                        // indicates the sent checksum and the checksum the client computed are the
                        // same.
                        //
                        // 2) a retransmission packet, in wich case the client sends back whatever
                        // checksum it receives. If retransmission is requested, then the server starts
                        // sending the buffer it sends before.

                        int payload_integrity = 1;
                        memset(pmsg, 0, SHAKESIZE);
                        read(acceptdf, pmsg, SHAKESIZE);
                        sscanf(pmsg, "%d", &payload_integrity);

                        if (payload_integrity == 1) {
                            getpeername(acceptdf, (struct sockaddr*)&address, (socklen_t*)&addrlen);
                            printf("client on port %d received integral payload.\n", ntohs(address.sin_port));

                        }
                        else {
                            int trials;
                            for (trials = 1; trials <= MAX_RETRANSM; trials++) {
                                memset(buffer, 0, bufsize);
                                serialize_header(buffer, header);
                                memcpy(&buffer[13], payload, header.len);
                                write(acceptdf, buffer, bufsize);

                                memset(pmsg, 0, SHAKESIZE);
                                read(acceptdf, pmsg, SHAKESIZE);
                                sscanf(pmsg, "%d", &payload_integrity);

                                if (VERBOSE_PRINT) {
                                    printf("server is sending header + payload from server.\n");
                                    printf("\t");
                                    print_header(header);
                                    printf("\t");
                                    printf("payload: %s\n", payload);
                                    printf("\n");
                                }

                                if (payload_integrity == 1) {
                                    getpeername(acceptdf, (struct sockaddr*)&address, (socklen_t*)&addrlen);
                                    printf("client on port %d received integral payload.\n", ntohs(address.sin_port));
                                    break;
                                }
                                else {
                                    delay(5);
                                }
                            }

                            if (trials > MAX_RETRANSM) {
                                printf("Error: server exceeded retransmission of payload. Connection closed.\n");
                                close(acceptdf);
                                exit(0);
                            }
                        }

                        //////////////////////////////////////////////////////////////////////////////
                        // END: CHECK THE PAYLOAD'S INTEGRITY.
                        //////////////////////////////////////////////////////////////////////////////
		    		}
		    	}
		    }
        }
	}

	return 0;
} //  MAIN



uint16_t ichecksum(uint16_t *addr, int len) {
    /*
    Compute Internet Checksum for "count" bytes beginning at location "addr".

    Taken from https://tools.ietf.org/html/rfc1071
    */

    uint32_t sum  = 0;
    uint16_t *ptr = addr;
    int count     = len;

    while (count > 1) {
        sum += *ptr++;
        count -= 2;
    }

    // add left-over byte, if any.
    if (count > 0) {
       sum = sum + *(uint8_t *) ptr;
    }

    // fold 32-bit sum to 16 bits
    while (sum >> 16) {
        sum = (sum & 0xffff) + (sum >> 16);
    }

    return ~sum;
}

void pack_uint16_t(char *buffer, uint16_t value) {
    buffer[0] = value;
    buffer[1] = value >> 8;
}

uint16_t unpack_uint16_t(char *buffer) {
    return (uint8_t)buffer[1] << 8 | (uint8_t)buffer[0];
}

void pack_uint8_t(char *buffer, uint8_t value) {
    buffer[0] = value;
}

uint16_t unpack_uint8_t(char *buffer) {
    return buffer[0];
}

void serialize_header(char *buffer, struct capshdr header) {
    pack_uint8_t(&buffer[0], header.version);   // 1 byte
    pack_uint16_t(&buffer[1], header.ack);      // 2 bytes
    pack_uint16_t(&buffer[3], header.syn);      // 2 bytes
    pack_uint16_t(&buffer[5], header.seq);      // 2 bytes
    pack_uint16_t(&buffer[7], header.bufsize);  // 2 bytes
    pack_uint16_t(&buffer[9], header.checksum); // 2 bytes
    pack_uint16_t(&buffer[11], header.len);     // 2 bytes
}

void deserialize_header(char *buffer, struct capshdr *header) {
    header->version  = unpack_uint8_t(&buffer[0]);
    header->ack      = unpack_uint16_t(&buffer[1]);
    header->syn      = unpack_uint16_t(&buffer[3]);
    header->seq      = unpack_uint16_t(&buffer[5]);
    header->bufsize  = unpack_uint16_t(&buffer[7]);
    header->checksum = unpack_uint16_t(&buffer[9]);
    header->len      = unpack_uint16_t(&buffer[11]);
}

void delay(unsigned int secs) {
    /*
    Create a delay of secs.
    Dependency: time.h
    Source: https://stackoverflow.com/a/3930477
    */
    unsigned int retTime = time(0) + secs;   // Get finishing time.
    while (time(0) < retTime);               // Loop until it arrives.
}

void print_header(struct capshdr header) {
    printf(
        "VER: %d ACK: %d SYN: %d SEQ: %d BUFSIZE: %d CS: %d LEN: %d\n",
        header.version, header.ack, header.syn, header.seq, header.bufsize, header.checksum, header.len
    );
}

int check(int exp, const char *msg) {
    if (exp == -1) {
        perror(msg);
        exit(1);
    }
    return exp;
}

int setup_server(short port, int backlog) {
    int server_socket, client_socket, addr_size;
    struct sockaddr_in server_addr;

    server_socket = socket(AF_INET, SOCK_STREAM, 0);

	int opt = 1;
	//set master socket to allow multiple connections ,
	int sso = setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, (char *)&opt, sizeof(opt));
    if (sso < 0) {
		perror("setsockopt");
		exit(EXIT_FAILURE);
	}
    // check(server_socket, "socket() failed");

    server_addr.sin_family      = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port        = htons(port);

    int bindres = bind(server_socket, (struct sockaddr*)&server_addr, sizeof(server_addr));
    check(bindres, "bind() failed");

    int listenres = listen(server_socket, backlog);
    check(listenres, "listen() failed");
    printf("*** server is listening on port: %d ***\n", port);

    return server_socket;
}
