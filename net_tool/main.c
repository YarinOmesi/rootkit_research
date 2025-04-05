#include <stdio.h>
#include <sys/socket.h>
#include <string.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>

#define BUFFER_SIZE 1024

char buffer[BUFFER_SIZE];

const char *SERVER = "server";
const char *CLIENT = "client";

const int ARG_MODE = 1;
const int ARG_ADDR = 2;
const int ARG_PORT = 3;
const int ARG_MESSAGE = 4;

void print_usage();

void server(struct in_addr addr, int port);

void client(struct in_addr dest_addr, int port, char *message);


int main(int argc, char *argv[]) {
    // zero the buffer
    memset(buffer, 0, BUFFER_SIZE);

    // cli <tool> <server / client> <addr> <port> <string message>?

    if (argc < 2) {
        printf("Not enogh arguments\n");
        print_usage();
        return 1;
    }

    struct in_addr in_addr = {0};

    // parse address
    {
        char *addr = argv[ARG_ADDR];

        char *ip_buffer = (char *) &in_addr.s_addr;

        // big endian
        int count = sscanf(addr, "%hhd.%hhd.%hhd.%hhd", &(ip_buffer[0]), &(ip_buffer[1]), &(ip_buffer[2]),
                           &(ip_buffer[3]));

        if (count != 4) {
            fprintf(stderr, "cant parse address %s\n", addr);
            return 1;
        }
    }

    int port = atoi(argv[ARG_PORT]);

    printf("%s:%d\n", inet_ntoa(in_addr), port);

    if (strcmp(argv[ARG_MODE], SERVER) == 0) {
        server(in_addr, port);
    } else if (strcmp(argv[ARG_MODE], CLIENT) == 0) {
        if (argc == 5) {
            client(in_addr, port, argv[ARG_MESSAGE]);
        } else {
            print_usage();
            return 1;
        }

    } else {
        fprintf(stderr, "Only allow server or client\n");
        print_usage();
        return 1;
    }

    return 0;
}

void server(struct in_addr host_addr, int port) {
    printf("Starting server at %s:%d\n", inet_ntoa(host_addr), port);
    int socket_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    struct sockaddr_in addr = {0};

    addr.sin_family = AF_INET;
    addr.sin_addr = host_addr;
    addr.sin_port = ntohs(port);


    int result = bind(socket_fd, (struct sockaddr *) &addr, sizeof(addr));

    if (result == -1) {
        fprintf(stderr, "Cant bind server %d\n", errno);
        return;
    } else {
        printf("bind server\n");
    }

    ssize_t bytes_read = recvfrom(socket_fd, buffer, BUFFER_SIZE, 0, NULL, NULL);
    if (bytes_read == -1) {
        fprintf(stderr, "Error: %d\n", errno);
    } else {
        printf("Message Received: %s\n", buffer);
    }


    close(socket_fd);
}

void client(struct in_addr dest_addr, int port, char *message) {
    int socket_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    struct sockaddr_in addr = {0};

    addr.sin_family = AF_INET;
    addr.sin_addr = dest_addr;
    addr.sin_port = ntohs(port);

    // Copy Message To The Buffer
    strcpy(buffer, message);

    size_t len = strlen(message);

    ssize_t bytes_read = sendto(socket_fd, (void *) buffer, len, 0, (struct sockaddr *) &addr,
                                sizeof(struct sockaddr_in));
    if (bytes_read == -1) {
        fprintf(stderr, "Error: %d\n", errno);
    } else {
        printf("Message Sent: %s\n", buffer);
    }

    close(socket_fd);
}

void print_usage() {
    printf("Usage:\n\tnetool <server/client> <port> <message>?\n\t message supported only when in client mode\n");
}