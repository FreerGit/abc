#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#include <liburing.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define SERVER "www.example.com"
#define PORT   443
#define QUEUE_DEPTH  2

int setup_io_uring(struct io_uring *ring) {
    if (io_uring_queue_init(QUEUE_DEPTH, ring, 0) < 0) {
        perror("io_uring_queue_init");
        return -1;
    }
    return 0;
}

int connect_to_server(const char *hostname, int port) {
    struct sockaddr_in server_addr;
    struct hostent *server;

    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("socket");
        return -1;
    }

    server = gethostbyname(hostname);
    if (server == NULL) {
        fprintf(stderr, "No such host: %s\n", hostname);
        close(sockfd);
        return -1;
    }

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    memcpy(&server_addr.sin_addr.s_addr, server->h_addr, server->h_length);

    if (connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("connect");
        close(sockfd);
        return -1;
    }

    return sockfd;
}

int main() {
    struct io_uring ring;
    WOLFSSL_CTX *ctx;
    WOLFSSL *ssl;
    int sockfd;
    char request[] = "GET / HTTP/1.1\r\nHost: " SERVER "\r\nConnection: close\r\n\r\n";
    char buffer[4096];

    // Initialize io_uring
    if (setup_io_uring(&ring) < 0) {
        return -1;
    }

    // Initialize wolfSSL
    wolfSSL_Init();
    ctx = wolfSSL_CTX_new(wolfTLSv1_3_client_method());
    if (!ctx) {
        fprintf(stderr, "wolfSSL_CTX_new error.\n");
        return -1;
    }

    ssl = wolfSSL_new(ctx);
    if (!ssl) {
        fprintf(stderr, "wolfSSL_new error.\n");
        wolfSSL_CTX_free(ctx);
        return -1;
    }

    // Connect to the server
    sockfd = connect_to_server(SERVER, PORT);
    if (sockfd < 0) {
        wolfSSL_free(ssl);
        wolfSSL_CTX_free(ctx);
        return -1;
    }

    // Set the file descriptor for wolfSSL
    wolfSSL_set_fd(ssl, sockfd);

    // Establish TLS connection
    if (wolfSSL_connect(ssl) != SSL_SUCCESS) {
        fprintf(stderr, "wolfSSL_connect error.\n");
        wolfSSL_free(ssl);
        wolfSSL_CTX_free(ctx);
        close(sockfd);
        return -1;
    }

    // Prepare io_uring submission queue entry (SQE) for sending data
    struct io_uring_sqe *sqe = io_uring_get_sqe(&ring);
    if (!sqe) {
        fprintf(stderr, "io_uring_get_sqe error.\n");
        wolfSSL_free(ssl);
        wolfSSL_CTX_free(ctx);
        close(sockfd);
        return -1;
    }

    io_uring_prep_send(sqe, sockfd, request, strlen(request), 0);
    io_uring_submit(&ring);

    // Prepare io_uring completion queue entry (CQE)
    struct io_uring_cqe *cqe;
    io_uring_wait_cqe(&ring, &cqe);
    if (cqe->res < 0) {
        fprintf(stderr, "io_uring_send error: %d\n", cqe->res);
        io_uring_cqe_seen(&ring, cqe);
        wolfSSL_free(ssl);
        wolfSSL_CTX_free(ctx);
        close(sockfd);
        return -1;
    }
    io_uring_cqe_seen(&ring, cqe);

    // Prepare io_uring SQE for receiving data
    sqe = io_uring_get_sqe(&ring);
    if (!sqe) {
        fprintf(stderr, "io_uring_get_sqe error.\n");
        wolfSSL_free(ssl);
        wolfSSL_CTX_free(ctx);
        close(sockfd);
        return -1;
    }

    io_uring_prep_recv(sqe, sockfd, buffer, sizeof(buffer) - 1, 0);
    io_uring_submit(&ring);

    // Wait for the CQE
    io_uring_wait_cqe(&ring, &cqe);
    if (cqe->res < 0) {
        fprintf(stderr, "io_uring_recv error: %d\n", cqe->res);
    } else {
        buffer[cqe->res] = '\0';
        printf("%s\n", buffer);
    }
    io_uring_cqe_seen(&ring, cqe);

    // Cleanup
    wolfSSL_shutdown(ssl);
    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
    close(sockfd);
    io_uring_queue_exit(&ring);
    wolfSSL_Cleanup();

    return 0;
}
