#include <stdio.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <string.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>

#define BUFFER_SIZE 1024

char buffer[BUFFER_SIZE];

const char* SERVER = "server";
const char* CLIENT = "client";

const int ARG_INDEX = 1;
const int ARG_PORT = 2;
const int ARG_MESSAGE = 3;

void print_usage();

void server(int port);

void client(int port, char* message);


int main(int argc, char* argv[]){
    // zero the buffer
    memset(buffer, 0, BUFFER_SIZE);

    // cli <tool> <server / client> <port> <string message>?

    if(argc < 2){
        printf("Not enogh arguments\n");
        print_usage();
        return 1;
    }

    int port = atoi(argv[ARG_PORT]);

    if(strcmp(argv[ARG_INDEX], SERVER) == 0){
        server(port);
    } else if(strcmp(argv[ARG_INDEX], CLIENT) == 0){
        if(argc == 4) {
            client(port, argv[ARG_MESSAGE]);
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

void server(int port) {
    printf("Starting server at 0.0.0.0:%d\n", port);
    int socket_fd = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in addr;

    memset(&addr, 0, sizeof(struct sockaddr_in));

    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY); // 0.0.0.0
    addr.sin_port = ntohs(port);


	int result = bind(socket_fd, (struct sockaddr*)&addr, sizeof(addr));

    if(result == -1){
        fprintf(stderr, "Cant bind server %d\n", errno);
        return;
    }else{
        printf("bind server\n");
    }


    int bytes_read = recvfrom(socket_fd, buffer, BUFFER_SIZE, 0, NULL, NULL);
    if(bytes_read == -1){
        fprintf(stderr, "Error: %d\n", errno);
    } else{
        printf("Message Received: %s\n", buffer);
    }

    
    close(socket_fd);
}

void client(int port, char* message){
    int socket_fd = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in addr;

    memset(&addr, 0, sizeof(struct sockaddr_in));

    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY); // 0.0.0.0
    addr.sin_port = ntohs(port);

    // Copy Message To The Buffer
    strcpy(buffer, message);

    int bytes_read = sendto(socket_fd, (void*)buffer, BUFFER_SIZE, 0, (struct sockaddr*)&addr, sizeof(struct sockaddr_in));
    if(bytes_read == -1){
        fprintf(stderr, "Error: %d\n", errno);
    }else{
        printf("Message Sent: %s\n", buffer);
    }
    
    close(socket_fd);
}



void print_usage() {
    printf("Usage:\n\tnetool <server/client> <port> <message>?\n\t message supported only when in client mode\n");
}