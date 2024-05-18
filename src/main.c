#define LOG_DEBUG
#define LOG_WITH_TIME
#define _ATFILE_SOURCE
#include "log.h"
#include <arpa/inet.h>
#include <bits/types/sigset_t.h>
#include <fcntl.h>
#include <fcntl.h> // Include this header for AT_FDCWD
#include <liburing.h>
#include <netdb.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <wolfssl/options.h>
#include <wolfssl/ssl.h>

#define QUEUE_DEPTH 64
#define MAX_BUFFER_SIZE 4096

int main() {
  // Initialize WolfSSL
  wolfSSL_Init();

  // Create a WolfSSL context
  WOLFSSL_CTX *ctx = wolfSSL_CTX_new(wolfTLSv1_2_client_method());
  if (ctx == NULL) {
    fprintf(stderr, "Failed to create WolfSSL context\n");
    return 1;
  }

  // Create a socket and connect to www.example.com
  int sockfd = socket(AF_INET, SOCK_STREAM, 0);
  if (sockfd < 0) {
    fprintf(stderr, "Failed to create socket\n");
    return 1;
  }

  struct sockaddr_in server_addr;
  memset(&server_addr, 0, sizeof(server_addr));
  server_addr.sin_family = AF_INET;
  server_addr.sin_port = htons(443);                                     // HTTPS port
  if (inet_pton(AF_INET, "93.184.215.14", &server_addr.sin_addr) <= 0) { // www.example.com IP
    fprintf(stderr, "Invalid address\n");
    return 1;
  }

  if (connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
    fprintf(stderr, "Failed to connect to server\n");
    return 1;
  }

  // Create a WolfSSL object
  WOLFSSL *ssl = wolfSSL_new(ctx);
  if (ssl == NULL) {
    fprintf(stderr, "Failed to create WolfSSL object\n");
    return 1;
  }

  // Attach the socket to the WolfSSL object
  wolfSSL_set_fd(ssl, sockfd);

  // Perform the TLS/SSL handshake
  int ret = wolfSSL_connect(ssl);
  if (ret != SSL_SUCCESS) {
    fprintf(stderr, "Failed to perform TLS/SSL handshake\n");
    return 1;
  }

  // Set up liburing 2.5
  struct io_uring ring;
  io_uring_queue_init(QUEUE_DEPTH, &ring, 0);

  // Allocate buffers for read and write operations
  char read_buffer[MAX_BUFFER_SIZE];
  char write_buffer[] = "GET / HTTP/1.1\r\nHost:www.example.com\r\n\r\n";

  // Send the GET request
  struct io_uring_sqe *sqe = io_uring_get_sqe(&ring);
  io_uring_prep_send(sqe, sockfd, write_buffer, strlen(write_buffer), 0);
  io_uring_submit(&ring);

  // Wait for the write operation to complete
  struct io_uring_cqe *cqe;
  io_uring_wait_cqe(&ring, &cqe);
  perror("write");
  io_uring_cqe_seen(&ring, cqe);

  // Read the response
  sqe = io_uring_get_sqe(&ring);
  struct iovec *req = malloc(sizeof(struct iovec));
  req->iov_base = malloc(MAX_BUFFER_SIZE);
  req->iov_len = MAX_BUFFER_SIZE;
  memset(req->iov_base, 0, MAX_BUFFER_SIZE);
  /* Linux kernel 5.5 has support for readv, but not for recv() or read() */
  io_uring_prep_readv(sqe, sockfd, req, 1, 0);
  io_uring_sqe_set_data(sqe, req);
  io_uring_submit(&ring);

  ret = io_uring_wait_cqe(&ring, &cqe);
  perror("read");

  struct iovec *data = (struct iovec *)io_uring_cqe_get_data(cqe);

  log_info("%d, %.*s", req->iov_len, data->iov_len, data->iov_base);
  io_uring_cqe_seen(&ring, cqe);

    free(req->iov_base);
  free(req);
  // Clean up
  io_uring_queue_exit(&ring);
  wolfSSL_free(ssl);
  wolfSSL_CTX_free(ctx);
  wolfSSL_Cleanup();

  return 0;
}