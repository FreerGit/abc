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

struct io_uring ring;
struct io_uring_cqe *cqe;

void prep_read(int fd, struct io_uring *ring, size_t max_buff_size) {
  struct io_uring_sqe *sqe = io_uring_get_sqe(ring);
  if (!sqe) {
    log_fatal("could not get sqe");
  }

  // io_uring_prep_recv(sqe, fd, NULL, max_buff_size, 0);
  // sqe->flags |= IOSQE_BUFFER_SELECT;
  // sqe->buf_group = 0;
  struct iovec *req = malloc(sizeof(struct iovec));
  req->iov_base = malloc(max_buff_size);
  req->iov_len = max_buff_size;
  // memset(&sqe->user_data, 0, max_buff_size);
  memcpy(&sqe->user_data, &req, sizeof(req));
  io_uring_prep_readv(sqe, fd, req, 1, 0);
  perror("read");

  io_uring_sqe_set_data(sqe, req);
  perror("set");
  io_uring_submit(ring);
  perror("submit");
}

// void on_data_recv(struct io_uring *ring, struct io_uring_cqe *cqe) {
// }

int CbIORecv(WOLFSSL *ssl, char *buf, int sz, void *ctx) {
  log_info("waiting");
  (void)ssl;
  int sockfd = *(int *)ctx;
  int ret = 0;
  prep_read(sockfd, &ring, sz);

  int ret_ret = io_uring_wait_cqe(&ring, &cqe);
  perror("waiting");
  // memcpy(buf, &cqe->user_data, read_bytes);
  struct iovec *data = (struct iovec *)cqe->user_data;
  log_debug("%d, %s", cqe->res, buf);

  memcpy(buf, data->iov_base, cqe->res);
  // buf = data->iov_base;
  ret = cqe->res;
  sz = cqe->res;

  io_uring_cqe_seen(&ring, cqe);
  // printf("/*-------------------- CLIENT READING -----------------*/\n");
  // for (int i = 0; i < ret; i++) {
  //   printf("%02X ", *((unsigned char *)buf + i));
  //   if (i > 0 && (i % 16) == 0)
  //     printf("\n");
  // }
  // printf("\n/*-------------------- CLIENT READING -----------------*/\n");

  //   if ((ret = (int)read(sockfd, buf, (size_t)sz)) == -1) {
  //     /* error encountered. Be responsible and report it in wolfSSL terms */

  //     fprintf(stderr, "IO RECEIVE ERROR: ");
  //     switch (errno) {
  // #if EAGAIN != EWOULDBLOCK
  //     case EAGAIN: /* EAGAIN == EWOULDBLOCK on some systems, but not others */
  // #endif
  //     case EWOULDBLOCK:
  //       if (!wolfSSL_dtls(ssl) || wolfSSL_get_using_nonblock(ssl)) {
  //         fprintf(stderr, "would block\n");
  //         return WOLFSSL_CBIO_ERR_WANT_READ;
  //       } else {
  //         fprintf(stderr, "socket timeout\n");
  //         return WOLFSSL_CBIO_ERR_TIMEOUT;
  //       }
  //     case ECONNRESET:
  //       fprintf(stderr, "connection reset\n");
  //       return WOLFSSL_CBIO_ERR_CONN_RST;
  //     case EINTR:
  //       fprintf(stderr, "socket interrupted\n");
  //       return WOLFSSL_CBIO_ERR_ISR;
  //     case ECONNREFUSED:
  //       fprintf(stderr, "connection refused\n");
  //       return WOLFSSL_CBIO_ERR_WANT_READ;
  //     case ECONNABORTED:
  //       fprintf(stderr, "connection aborted\n");
  //       return WOLFSSL_CBIO_ERR_CONN_CLOSE;
  //     default:
  //       fprintf(stderr, "general error\n");
  //       return WOLFSSL_CBIO_ERR_GENERAL;
  //     }
  //   } else if (ret == 0) {
  //     printf("Connection closed\n");
  //     return WOLFSSL_CBIO_ERR_CONN_CLOSE;
  //   }

  log_debug("%d", ret);
  // Read the response
  // struct io_uring_sqe *sqe = io_uring_get_sqe(&ring);
  // struct iovec *req = malloc(sizeof(struct iovec));
  // req->iov_base = malloc(MAX_BUFFER_SIZE);
  // req->iov_len = MAX_BUFFER_SIZE;
  // memset(req->iov_base, 0, MAX_BUFFER_SIZE);

  // io_uring_prep_readv(sqe, sockfd, req, 1, 0);
  // perror("read");
  // io_uring_sqe_set_data(sqe, req);
  // perror("read");
  // io_uring_submit(&ring);
  // perror("read");

  // int ret_ret = io_uring_wait_cqe(&ring, &cqe);
  // perror("read");
  // struct iovec *data = (struct iovec *)cqe->user_data;
  // log_debug("%d, %s", cqe->res, data->iov_base);

  // buf = ((char *)((struct iovec *)cqe->user_data)[0].iov_base);
  // sz = cqe->res;

  // io_uring_cqe_seen(&ring, cqe);
  // free(req->iov_base);
  // free(req);

  // printf("/*-------------------- CLIENT READING -----------------*/\n");
  // for (int i = 0; i < cqe->res; i++) {
  //   printf("%02X ", *((unsigned char *)buf + i));
  //   if (i > 0 && (i % 16) == 0)
  //     printf("\n");
  // }
  // printf("\n/*-------------------- CLIENT READING -----------------*/\n");

  return ret;
}

int CbIOSend(WOLFSSL *ssl, char *buf, int sz, void *ctx) {
  (void)ssl; /* will not need ssl context, just using the file system */
  int sockfd = *(int *)ctx;
  int sent;

  /* Receive message from socket */
  if ((sent = send(sockfd, buf, sz, 0)) == -1) {
    /* error encountered. Be responsible and report it in wolfSSL terms */

    fprintf(stderr, "IO SEND ERROR: ");
    switch (errno) {
#if EAGAIN != EWOULDBLOCK
    case EAGAIN: /* EAGAIN == EWOULDBLOCK on some systems, but not others */
#endif
    case EWOULDBLOCK:
      fprintf(stderr, "would block\n");
      return WOLFSSL_CBIO_ERR_WANT_WRITE;
    case ECONNRESET:
      fprintf(stderr, "connection reset\n");
      return WOLFSSL_CBIO_ERR_CONN_RST;
    case EINTR:
      fprintf(stderr, "socket interrupted\n");
      return WOLFSSL_CBIO_ERR_ISR;
    case EPIPE:
      fprintf(stderr, "socket EPIPE\n");
      return WOLFSSL_CBIO_ERR_CONN_CLOSE;
    default:
      fprintf(stderr, "general error\n");
      return WOLFSSL_CBIO_ERR_GENERAL;
    }
  } else if (sent == 0) {
    printf("Connection closed\n");
    return 0;
  }

  /* successful send */
  printf("my_IOSend: sent %d bytes to %d\n", sz, sockfd);
  return sent;
}

int main() {

  // Set up liburing 2.5
  if (io_uring_queue_init(QUEUE_DEPTH, &ring, 0) < 0) {
    perror("io_uring_queue_init");
    return -1;
  }

  // Initialize WolfSSL
  wolfSSL_Init();

  // Create a WolfSSL context
  WOLFSSL_CTX *ctx = wolfSSL_CTX_new(wolfSSLv23_client_method());
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

  wolfSSL_SetIORecv(ctx, CbIORecv);
  wolfSSL_SetIOSend(ctx, CbIOSend);

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
    perror("connect");
    // log_error("Connect: %d", );
    char errorString[80];
    int err_c = wolfSSL_get_error(ssl, ret);
    log_error("%d", err_c);
    wolfSSL_ERR_error_string(err_c, errorString);
    log_error("%s", errorString);
    fprintf(stderr, "Failed to perform TLS/SSL handshake\n");
    return 1;
  }

  // Allocate buffers for read and write operations
  char read_buffer[MAX_BUFFER_SIZE];
  char write_buffer[] = "GET / HTTP/1.1\r\nHost:www.example.com\r\n\r\n";

  // Send the GET request
  // struct io_uring_sqe *sqe = io_uring_get_sqe(&ring);
  // io_uring_prep_send(sqe, sockfd, write_buffer, strlen(write_buffer), 0);
  // io_uring_submit(&ring);

  // // Wait for the write operation to complete
  // io_uring_wait_cqe(&ring, &cqe);
  // perror("write");
  // io_uring_cqe_seen(&ring, cqe);

  // log_info("%d, %.*s", data->iov_len, data->iov_len, data->iov_base);
  // log_info("%d, %.*s", req->iov_len, req->iov_len, req->iov_base);
  // log_info("%d, BEGIN%.*XEND", cqe->res, cqe->res, data->iov_base);
  // log_info("%d, BEGIN%.*XEND", cqe->res, cqe->res, req[0].iov_base);

  if ((ret = wolfSSL_write(ssl, write_buffer, strlen(write_buffer))) != strlen(write_buffer)) {
    fprintf(stderr, "ERROR: failed to write\n");
    // goto exit;
  }

  int r;
  char buff[MAX_BUFFER_SIZE];
  memset(buff, 0, sizeof(buff));

  // prep_read(sockfd, &ring, MAX_BUFFER_SIZE);

  if ((r = wolfSSL_read(ssl, buff, sizeof(buff) - 1)) == -1) {
    fprintf(stderr, "ERROR: failed to read\n");
  }
  log_debug("read: %d", r);
  log_info("%s", buff);
  // for (int i = 0; i < 1; i++) {
  //   printf("iov[%d]: ", i);
  //   for (int j = 0; j < cqe->res; j++) {
  //     printf("%02X ", *((unsigned char *)data[i].iov_base + j));
  //   }
  //   printf("\n");
  // }

  // free(req->iov_base);
  // free(req);
  // Clean up
  // io_uring_queue_exit(&ring);
  // wolfSSL_free(ssl);
  // wolfSSL_CTX_free(ctx);
  // wolfSSL_Cleanup();

  return 0;
}