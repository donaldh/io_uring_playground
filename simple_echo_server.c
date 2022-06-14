#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <liburing.h>
#include <argp.h>

#define SERVER_PORT 3333
#define QUEUE_DEPTH 256
#define READ_SIZE   1024

enum event_type {
    ACCEPT,
    READ,
    WRITE,
    CLOSE
};

int async_sqes = 0;
int debug = 0;

struct request {
    enum event_type type;
    int socket;
    int iovec_count;
    struct iovec iov[];
};

struct io_uring ring;

void signal_handler(int num) {
    printf("Exiting\n");
    io_uring_queue_exit(&ring);
    exit(0);
}

void fatal_error(const char *syscall) {
    perror(syscall);
    exit(1);
}

int add_accept_request(int listen_socket,
                       struct sockaddr_in *client_addr,
                       socklen_t *client_addr_len) {
    struct io_uring_sqe *sqe = io_uring_get_sqe(&ring);
    io_uring_prep_accept(sqe,
                         listen_socket,
                         (struct sockaddr *) client_addr,
                         client_addr_len,
                         0);
    struct request *req = malloc(sizeof(struct request));
    req->type = ACCEPT;
    io_uring_sqe_set_data(sqe, req);
    if (async_sqes) {
        io_uring_sqe_set_flags(sqe, IOSQE_ASYNC);
    }

    return 0;
}

int add_read_request(int socket) {
    struct io_uring_sqe *sqe = io_uring_get_sqe(&ring);
    struct request *req = malloc(sizeof(*req) + sizeof(struct iovec));
    req->iov[0].iov_base = malloc(READ_SIZE);
    req->iov[0].iov_len = READ_SIZE;
    req->type = READ;
    req->socket = socket;
    memset(req->iov[0].iov_base, 0, READ_SIZE);

    io_uring_prep_readv(sqe, socket, &req->iov[0], 1, 0);
    io_uring_sqe_set_data(sqe, req);
    if (async_sqes)
        io_uring_sqe_set_flags(sqe, IOSQE_ASYNC);

    return 0;
}

int add_write_request(struct request *req) {
    struct io_uring_sqe *sqe = io_uring_get_sqe(&ring);
    req->type = WRITE;
    io_uring_prep_writev(sqe, req->socket, req->iov, 1, 0);
    io_uring_sqe_set_data(sqe, req);
    if (async_sqes)
        io_uring_sqe_set_flags(sqe, IOSQE_ASYNC);

    return 0;
}

int add_close_request(int socket) {
    struct io_uring_sqe *sqe = io_uring_get_sqe(&ring);
    struct request *req = malloc(sizeof(*req) + sizeof(struct iovec));
    req->type = CLOSE;
    io_uring_prep_close(sqe, socket);
    io_uring_sqe_set_data(sqe, req);
    if (async_sqes)
        io_uring_sqe_set_flags(sqe, IOSQE_ASYNC);

    return 0;
}

void main_loop(int listen_socket) {
    struct io_uring_cqe *cqe;
    struct sockaddr_in client_addr;
    socklen_t client_addr_len = sizeof(client_addr);

    unsigned space = io_uring_sq_space_left(&ring);
    while (space > 0) {
        add_accept_request(listen_socket, &client_addr, &client_addr_len);
        space--;
    }
    io_uring_submit(&ring);

    int close_count = 0;

    while (1) {
        int ret = io_uring_wait_cqe(&ring, &cqe);
        if (ret < 0) {
            fatal_error("io_uring_wait_cqe");
        }

        struct request *req = (struct request*) cqe->user_data;
        if (cqe->res < 0) {
            fprintf(stderr, "Async request failed: %s for event: %d\n",
                    strerror(-cqe->res), req->type);
            exit(1);
        }

        switch (req->type) {
        case ACCEPT:
            if (debug) fprintf(stderr, "ACCEPT %d\n", cqe->res);
            add_accept_request(listen_socket, &client_addr, &client_addr_len);
            add_read_request(cqe->res);
            io_uring_submit(&ring);
            free(req);
            break;
        case READ:
            if (debug) fprintf(stderr, "READ %d\n", cqe->res);
            if (cqe->res <= 0) {
                close_count++;
                fprintf(stderr, "Empty read, closing\n");
                close(req->socket);
                free(req->iov[0].iov_base);
                free(req);
                break;
            }
            add_write_request(req);
            add_close_request(req->socket);
            io_uring_submit(&ring);
            break;
        case WRITE:
            if (debug) fprintf(stderr, "WRITE %d\n", cqe->res);
            free(req->iov[0].iov_base);
            free(req);
            break;
        case CLOSE:
            if (debug) fprintf(stderr, "CLOSE %d\n", cqe->res);
            close_count++;
            free(req);
            break;
        }

        io_uring_cqe_seen(&ring, cqe);
    }
}

int create_listen(int port) {
    int sock;
    struct sockaddr_in addr;

    sock = socket(PF_INET, SOCK_STREAM, 0);
    if (sock == -1) {
        fatal_error("socket()");
    }

    int enable = 1;
    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int)) < 0) {
        fatal_error("setsockopt(SO_REUSEADDR)");
    }

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);

    if (bind(sock, (const struct sockaddr *)&addr, sizeof(addr)) < 0) {
        fatal_error("bind()");
    }

    if (listen(sock, 10) < 0) {
        fatal_error("listen()");
    }

    return sock;
}


const char argp_program_doc[] =
    "Simple echo server\n"
    "\n"
    "Usage: ./simple_echo_server\n";

static const struct argp_option opts[] = {
    {"async", 'a', 0, 0, "Submit async requests"},
    {"debug", 'd', 0, 0, "Provide debug output"},
    {},
};

error_t parse_opts (int key, char *arg, struct argp_state *state)
{
    switch (key) {
    case 'a':
        async_sqes = 1;
        break;
    case 'd':
        debug = 1;
        break;
    default:
      return ARGP_ERR_UNKNOWN;
    }
  return 0;
}

static const struct argp argp = {
    .options = opts,
    .parser = parse_opts,
    .doc = argp_program_doc,
};

int main(int argc, char *argv[]) {
    int err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
    if (err)
        return 0;

    int listen_socket = create_listen(SERVER_PORT);

    signal(SIGINT, signal_handler);
    io_uring_queue_init(QUEUE_DEPTH, &ring, 0);
    main_loop(listen_socket);

    return 0;
}
