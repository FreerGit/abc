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

#include "stx.h"

#define QUEUE_DEPTH 64
#define MAX_BUFFER_SIZE 4096

struct io_uring ring;
struct io_uring_cqe *cqe;

void prep_read(int fd, struct io_uring *ring, size_t max_buff_size) {
  struct io_uring_sqe *sqe = io_uring_get_sqe(ring);
  if (!sqe) {
    log_fatal("could not get sqe");
  }

  struct iovec *req = malloc(sizeof(struct iovec));
  req->iov_base = malloc(max_buff_size);
  req->iov_len = max_buff_size;

  memcpy(&sqe->user_data, &req, sizeof(req));
  io_uring_prep_readv(sqe, fd, req, 1, 0);
  perror("read");

  io_uring_sqe_set_data(sqe, req);
  perror("set");
  io_uring_submit(ring);
  perror("submit");
}

int CbIORecv(WOLFSSL *ssl, char *buf, int sz, void *ctx) {
  (void)ssl;
  int sockfd = *(int *)ctx;
  int ret = 0;

  prep_read(sockfd, &ring, sz);

  // int ret_ret = io_uring_wait_cqe(&ring, &cqe);
  int ret_ret;
  while (1) {
    ret_ret = io_uring_peek_cqe(&ring, &cqe);
    if (ret_ret == -EAGAIN) {
      // No completion yet, continue polling
      log_debug("continue");
      continue;
    } else if (ret_ret < 0) {
      io_uring_queue_exit(&ring);
      log_fatal("io_uring_peek_cqe: %s\n", strerror(-ret_ret));
      // return 1;
    } else {
      log_info("got data");
      break;
    }
  }

  // CHECK_TIME({

  struct iovec *data = (struct iovec *)cqe->user_data;
  // log_debug("%d, %s", cqe->res, buf);

  memcpy(buf, data->iov_base, cqe->res);
  ret = cqe->res;
  sz = cqe->res;

  io_uring_cqe_seen(&ring, cqe);
  // }, "read");
  log_debug("%d %d", ret, ret_ret);

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
  struct io_uring_params params;
  memset(&params, 0, sizeof(params));
  // params.flags = IORING_SETUP_IOPOLL;

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
  int sockfd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
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

  // if (connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
  //   fprintf(stderr, "Failed to connect to server\n");
  //   return 1;
  // }

  // Prepare the connect operation
  struct io_uring_sqe *sqe = io_uring_get_sqe(&ring);
  if (!sqe) {
    log_error("io_uring_get_sqe: queue is full\n");
    io_uring_queue_exit(&ring);
    close(sockfd);
    return 1;
  }
  io_uring_prep_connect(sqe, sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr));

  // Submit the request
  int conn_ret = io_uring_submit(&ring);
  if (conn_ret < 0) {
    log_error("io_uring_submit: %d\n", -conn_ret);
    io_uring_queue_exit(&ring);
    close(sockfd);
    return 1;
  }

  // Poll for completion
  while (1) {
    conn_ret = io_uring_peek_cqe(&ring, &cqe);
    if (conn_ret == -EAGAIN) {
      // No completion yet, continue polling
      continue;
    } else if (conn_ret < 0) {
      fprintf(stderr, "io_uring_peek_cqe: %s\n", strerror(-conn_ret));
      io_uring_queue_exit(&ring);
      close(sockfd);
      return 1;
    } else {
      break;
    }
  }

  // Process the completion
  if (cqe->res < 0) {
    log_debug("here %d", cqe->res);
    fprintf(stderr, "Async connect failed: %s\n", strerror(-cqe->res));
    io_uring_queue_exit(&ring);
    close(sockfd);
    return 1;
  }

  io_uring_cqe_seen(&ring, cqe);

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

  if ((ret = wolfSSL_write(ssl, write_buffer, strlen(write_buffer))) != strlen(write_buffer)) {
    fprintf(stderr, "ERROR: failed to write\n");
    // goto exit;
  }

  int r;
  char buff[MAX_BUFFER_SIZE];
  memset(buff, 0, sizeof(buff));

  if ((r = wolfSSL_read(ssl, buff, sizeof(buff) - 1)) == -1) {
    fprintf(stderr, "ERROR: failed to read\n");
  }
  log_debug("read: %d", r);
  log_info("%s", buff);

  io_uring_queue_exit(&ring);
  wolfSSL_free(ssl);
  wolfSSL_CTX_free(ctx);
  wolfSSL_Cleanup();

  return 0;
}