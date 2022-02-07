/******************************************************************************
Title       : client.c
Author      : Luis Filion
Course      : CS499 - Advanced Capstone (Hunter College)
Professor   : Soumik Dey
Created on  : Sept. 22, 2021
Name        : Single-server Multi-client Using C Sockets
Created on  : Sept. 22, 2021
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
Usage       : ./client
Build with  : gcc client.c -o client
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
#define CLIENT_ISN 1001
#define SHAKESIZE 256
#define BUFSIZE 4096
#define MAX_RETRANSM 3
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

void pack_uint8_t(char *buffer, uint8_t value);
uint16_t unpack_uint8_t(char *buffer);
void pack_uint16_t(char *buffer, uint16_t value);
uint16_t unpack_uint16_t(char *buffer);
void print_capshdr(struct capshdr header);
uint16_t ichecksum(uint16_t *addr, int len);

void serialize_header(char *buffer, struct capshdr header);
void deserialize_header(char *buffer, struct capshdr *header);

void delay(unsigned int secs);
void print_header(struct capshdr header);

int main() {
    int sockfd;

/******************************************************************************
* SETTING UP THE CLIENT'S SOCKET
******************************************************************************/

    // get the client's socket file descriptor.
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == -1) {
        printf("Socket creation failed.\n");
        exit(0);
    }

    // set up address over which to connect to the server.
    struct sockaddr_in servaddr;
    bzero(&servaddr, sizeof(servaddr));
    servaddr.sin_family      = AF_INET;
    servaddr.sin_addr.s_addr = inet_addr("127.0.0.1");
    servaddr.sin_port        = htons(PORT);

    // attempt to make a connection over the set-up address.
    int connfd = connect(sockfd, (struct sockaddr*)&servaddr, sizeof(servaddr));
    if (connfd == -1) {
        printf("Connection with the server failed.\n");
        exit(0);
    }

/******************************************************************************
* PERFORMING THREE-WAY HANDSHAKE
******************************************************************************/
    printf("+-------------------------------------------------------+\n");
    printf("|                        CLIENT                         |\n");
    printf("+-------------------------------------------------------+\n\n");

    char *hbuffer = malloc(SHAKESIZE * sizeof(char));
    char *hmsg = malloc(SHAKESIZE * sizeof(char));
    struct capshdr chandshake;

    ///////////////////////////////////////////////////////////////////////////
    // SYN: FIRST HANDSHAKE
    ///////////////////////////////////////////////////////////////////////////

    printf("# THREE-WAY HANDSHAKE\n\n");

    // client sends SYN packet to server.
    chandshake.version = 1;
    chandshake.ack     = 0;
    chandshake.syn     = 1;
    chandshake.seq     = CLIENT_ISN;
    chandshake.bufsize = BUFSIZE;

    serialize_header(hbuffer, chandshake);
    write(sockfd, hbuffer, SHAKESIZE);

    // receive SYN status.
    unsigned int syn_status = 1;
    memset(hmsg, 0, SHAKESIZE);
    read(sockfd, hmsg, SHAKESIZE);
    sscanf(hmsg, "%d", &syn_status);

    if (syn_status == 1) {
        printf("1) SYN sent.\n");
        // continue with SYN-ACK.
    }
    else {
        int trials;
        for (trials = 1; trials <= MAX_RETRANSM; trials++) {
            // send SYN packet to server.
            memset(hbuffer, 0, SHAKESIZE);
            serialize_header(hbuffer, chandshake);
            write(sockfd, hbuffer, SHAKESIZE);

            // receive SYN-ACK status from server.
            memset(hbuffer, 0, SHAKESIZE);
            read(sockfd, hmsg, SHAKESIZE);
            sscanf(hmsg, "%d", &syn_status);

            // server received SYN, thus break and continue with handshake.
            if (syn_status == 1) {
                printf("1) SYN sent.\n");
                break;
            }
            else {
                delay(5);
            }
        }

        if (trials > MAX_RETRANSM) {
            printf("Error: client exceeded retransmission attempts of SYN packet. Connection closed.\n");
            close(sockfd);
            exit(0);
        }
    }

    ///////////////////////////////////////////////////////////////////////////
    // SYN-ACK: SECOND HANDSHAKE
    ///////////////////////////////////////////////////////////////////////////

    // receive SYN-ACK from server.
    memset(hbuffer, 0, SHAKESIZE);
    read(sockfd, hbuffer, SHAKESIZE);
    chandshake.ack = unpack_uint16_t(&hbuffer[1]);
    chandshake.syn = unpack_uint16_t(&hbuffer[3]);
    chandshake.seq = unpack_uint16_t(&hbuffer[5]);

    // chandshake.ack -= 1;
    unsigned int synack_status = (chandshake.ack == (CLIENT_ISN + 1) && chandshake.syn == 1);
    if (synack_status == 1) {
        // send SYN-ACK status to server. 1 = SUCCESS
        memset(hmsg, 0, SHAKESIZE);
        sprintf(hmsg, "%d", 1);
        write(sockfd, hmsg, SHAKESIZE);
        printf("2) SYN-ACK received.\n");
        // continue with ACK.
    }
    else {
        // send SYN-ACK status to server. 0 = FAIL
        memset(hmsg, 0, SHAKESIZE);
        sprintf(hmsg, "%d", 0);
        write(sockfd, hmsg, SHAKESIZE);

        // receive server's SYN-ACK retransmission.
        for (;;) {
            memset(hbuffer, 0, SHAKESIZE);
            int read_bytes = read(sockfd, hbuffer, SHAKESIZE);

            if (read_bytes == 0) {
                printf("Error: server didn't send SYN-ACK packet. Connection closed.\n");
                close(sockfd);
                exit(0);
            }

            chandshake.ack = unpack_uint16_t(&hbuffer[1]);
            chandshake.syn = unpack_uint16_t(&hbuffer[3]);
            chandshake.seq = unpack_uint16_t(&hbuffer[5]);

            synack_status = ((chandshake.ack == (CLIENT_ISN + 1) && chandshake.syn == 1));
            if (synack_status == 1) {
                synack_status = 1;
                memset(hmsg, 0, SHAKESIZE);
                sprintf(hmsg, "%d", 1);
                write(sockfd, hmsg, SHAKESIZE);
                printf("2) SYN-ACK received.\n");

                // continue with ACK.
                break;
            }
            else {
                memset(hmsg, 0, SHAKESIZE);
                sprintf(hmsg, "%d", 0);
                write(sockfd, hmsg, SHAKESIZE);
            }
        }
    }

    ///////////////////////////////////////////////////////////////////////////
    // ACK: THIRD HANDSHAKE
    ///////////////////////////////////////////////////////////////////////////

    uint16_t tack = chandshake.ack;
    chandshake.ack = chandshake.seq + 1; // ACK = server's ISN + 1
    chandshake.syn = 0;                  // client already sent SYN.
    chandshake.seq = tack;                // server's ACK

    memset(hbuffer, 0, SHAKESIZE);
    serialize_header(hbuffer, chandshake);
    write(sockfd, hbuffer, SHAKESIZE);

    int ack_status = 1;
    memset(hmsg, 0, SHAKESIZE);
    read(sockfd, hmsg, SHAKESIZE);
    sscanf(hmsg, "%d", &ack_status);

    if (ack_status == 1) {
        printf("3) ACK sent.\n");
    }
    else {
        int trials;
        for (trials = 1; trials <= MAX_RETRANSM; trials++) {
            // send ACK packet to server.
            memset(hbuffer, 0, SHAKESIZE);
            serialize_header(hbuffer, chandshake);
            write(sockfd, hbuffer, SHAKESIZE);

            // receive ACK status from server.
            memset(hmsg, 0, SHAKESIZE);
            read(sockfd, hmsg, SHAKESIZE);
            sscanf(hmsg, "%d", &ack_status);

            if (ack_status == 1) {
                printf("3) ACK sent.\n");
                break;
                // continue...
            }
            else {
                delay(5);
            }
        }

        if (trials > MAX_RETRANSM) {
            printf("Error: client exceeded retransmission attempts of ACK packet. Connection closed.\n");
            close(sockfd);
            exit(0);
        }
    }

    free(hmsg);
    free(hbuffer);

    printf("\n");

/******************************************************************************
* HEADER + DATA EXCHANGE WITH DATA'S CHECKSUM
******************************************************************************/
    printf("# DATA EXCHANGE\n\n");

    // allocate buffer's size (including null character).
    char *buffer = malloc((BUFSIZE + 1) * sizeof(char*));
    struct capshdr header;

    if (buffer == NULL) {
        printf("Error allocating buffer.\n");
        exit(0);
    }

    //char message[1000], server_reply[2000];

	while (true) {
		printf("Enter message: ");
		scanf("%s", buffer);

		//Send some data
		if (send(sockfd, buffer, strlen(buffer), 0) < 0) {
			puts("Send failed");
			return 1;
		}

        memset(buffer, 0, BUFSIZE);

        // get ready to read from server
        read(sockfd, buffer, BUFSIZE);

        // unpack header
        header.version  = unpack_uint8_t(&buffer[0]);   // 1 bytes
        header.ack      = unpack_uint16_t(&buffer[1]);  // 2 bytes
        header.syn      = unpack_uint16_t(&buffer[3]);  // 2 bytes
        header.seq      = unpack_uint16_t(&buffer[5]);  // 2 bytes
        header.bufsize  = unpack_uint16_t(&buffer[7]);  // 2 bytes
        header.checksum = unpack_uint16_t(&buffer[9]);  // 2 bytes
        header.len      = unpack_uint16_t(&buffer[11]); // 2 bytes

        // deserialize_header(buffer, &header);
        // unpack data
        char *payload = malloc(header.len * sizeof(char));
        memcpy(payload, &buffer[13], header.len);

        ///////////////////////////////////////////////////////////////////////////
        // CHECK THAT CLIENT RECEIVES DATA.
        ///////////////////////////////////////////////////////////////////////////

        char *pmsg = malloc(SHAKESIZE * sizeof(char));

        unsigned int payload_status = strlen(payload) > 0;
        if (payload_status == 1) {
            memset(pmsg, 0, SHAKESIZE);
            sprintf(pmsg, "%d", 1);
            write(sockfd, pmsg, SHAKESIZE);
            printf("1) Client received payload.\n");
        }
        else {
            memset(pmsg, 0, SHAKESIZE);
            sprintf(pmsg, "%d", 0);
            write(sockfd, pmsg, SHAKESIZE);

            for (;;) {
                memset(buffer, 0, BUFSIZE);
                int read_bytes = read(sockfd, buffer, BUFSIZE);

                if (read_bytes == 0) {
                    printf("Error: server didn't send payload. Connection closed.\n");
                    close(sockfd);
                    exit(0);
                }

                // unpack header
                deserialize_header(buffer, &header);
                // unpack data
                memset(payload, 0, BUFSIZE);
                memcpy(payload, &buffer[13], header.len);

                if (VERBOSE_PRINT) {
                    printf("client is receiving header + payload from server.\n");
                    printf("\t");
                    print_header(header);
                    printf("\t");
                    printf("payload: %s\n", payload);
                    printf("\n");
                }

                payload_status = strlen(payload) > 0;
                if (payload_status == 1) {
                    memset(pmsg, 0, SHAKESIZE);
                    sprintf(pmsg, "%d", 1);
                    write(sockfd, pmsg, SHAKESIZE);
                    printf("1) Client received payload.\n");
                    break;
                }
                else {
                    memset(pmsg, 0, SHAKESIZE);
                    sprintf(pmsg, "%d", 0);
                    write(sockfd, pmsg, SHAKESIZE);
                }
            }
        }

        ///////////////////////////////////////////////////////////////////////////
        // CHECK THE PAYLOAD'S INTEGRITY.
        ///////////////////////////////////////////////////////////////////////////

        // Compute data's checksum and compare it to the received checksum. If they
        // match, then acknowledge the server. Acknowledging here means the client
        // sends the server the received checksum + 1, which the server checks to see
        // if it was acknowledged.
        //
        // If the checksums don't match, then send the same received checksum; this
        // instructs the server to retransmit the same packet.

        unsigned int payload_integrity = (header.checksum == ichecksum((uint16_t*)payload, strlen(payload)));
        if (payload_integrity == 1) {
            memset(pmsg, 0, SHAKESIZE);
            sprintf(pmsg, "%d", 1);
            write(sockfd, pmsg, SHAKESIZE);
            printf("2) Client received integral payload.\n");
        }
        else {
            memset(pmsg, 0, SHAKESIZE);
            sprintf(pmsg, "%d", 0);
            write(sockfd, pmsg, SHAKESIZE);

            for (;;) {
                memset(buffer, 0, BUFSIZE);
                int read_bytes = read(sockfd, buffer, BUFSIZE);

                if (read_bytes == 0) {
                    printf("Error: server didn't send payload. Connection closed.\n");
                    close(sockfd);
                    exit(0);
                }

                // unpack header
                deserialize_header(buffer, &header);
                // unpack data
                memset(payload, 0, BUFSIZE);
                memcpy(payload, &buffer[13], header.len);

                if (VERBOSE_PRINT) {
                    printf("client is receiving header + payload from server.\n");
                    printf("\t");
                    print_header(header);
                    printf("\t");
                    printf("payload: %s\n", payload);
                    printf("\n");
                }

                payload_integrity = (header.checksum == ichecksum((uint16_t*)payload, strlen(payload)));
                if (payload_integrity == 1) {
                    memset(pmsg, 0, SHAKESIZE);
                    sprintf(pmsg, "%d", 1);
                    write(sockfd, pmsg, SHAKESIZE);
                    printf("2) Client received integral payload.\n");
                    break;
                }
                else {
                    memset(pmsg, 0, SHAKESIZE);
                    sprintf(pmsg, "%d", 0);
                    write(sockfd, pmsg, SHAKESIZE);
                }
            }
        }

        printf("Received: %s\n", payload);
	}

//--------------------------------------------------------------------
    close(sockfd);

    return 0;
}
/* END */

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

void print_capshdr(struct capshdr header) {
    printf("version: %d\n", header.version);
    printf("checksum: %d\n", header.checksum);
    printf("length: %d\n", header.len);
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

