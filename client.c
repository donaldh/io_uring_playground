#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <liburing.h>
#include <netdb.h>
#include <argp.h>

#define QUEUE_DEPTH 256
#define READ_SIZE   1024

enum event_type {
    ACCEPT,
    READ,
    WRITE,
    CLOSE
};

struct request {
    enum event_type type;
    int client_socket;
    int iovec_count;
    struct iovec iov[];
};

struct io_uring ring;

#define DEFAULT_HOST "127.0.0.1";
#define DEFAULT_PORT "3333";

int debug = 0;
int num_ops = 10;
int concurrent_ops = 100;

void signal_handler(int num) {
    printf("Exiting\n");
    io_uring_queue_exit(&ring);
    exit(0);
}

void fatal_error(const char *syscall) {
    perror(syscall);
    exit(1);
}

void print_addr(struct addrinfo *addr) {
    char num_name[255];
    char num_serv[255];
    int status = getnameinfo(addr->ai_addr, addr->ai_addrlen, num_name, 255, num_serv, 255, NI_NUMERICHOST | NI_NUMERICSERV);
    if (status != 0) {
        fprintf(stderr, "getnameinfo: %s\n", gai_strerror(status));
        exit(EXIT_FAILURE);
    }
    fprintf(stderr, "Trying %s:%s\n", num_name, num_serv);
}

int client_connect(const char* host, const char* service) {
    int sock;

    struct addrinfo hints;
    struct addrinfo *result, *rp;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;     /* Allow IPv4 or IPv6 */
    hints.ai_socktype = SOCK_STREAM; /* TCP socket */
    hints.ai_flags = 0;
    hints.ai_protocol = 0;           /* Any protocol */

    int status = getaddrinfo(host, service, &hints, &result);
    if (status != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(status));
        exit(EXIT_FAILURE);
    }

    /* getaddrinfo() returns a list of address structures.
       Try each address until we successfully connect(2).
       If socket(2) (or connect(2)) fails, we (close the socket
       and) try the next address. */

    for (rp = result; rp != NULL; rp = rp->ai_next) {
        if (debug) print_addr(rp);

        sock = socket(rp->ai_family, rp->ai_socktype,
                      rp->ai_protocol);
        if (sock == -1)
            continue;

        if (connect(sock, rp->ai_addr, rp->ai_addrlen) != -1)
            break;                  /* Success */

        close(sock);
    }

    freeaddrinfo(result);           /* No longer needed */

    if (rp == NULL) {               /* No address succeeded */
        fprintf(stderr, "Could not connect\n");
        exit(EXIT_FAILURE);
    }

    return sock;
}

int add_read_request(int socket) {
    struct io_uring_sqe *sqe = io_uring_get_sqe(&ring);
    struct request *req = malloc(sizeof(*req) + sizeof(struct iovec));
    req->iov[0].iov_base = malloc(READ_SIZE);
    req->iov[0].iov_len = READ_SIZE;
    req->type = READ;
    req->client_socket = socket;
    memset(req->iov[0].iov_base, 0, READ_SIZE);

    io_uring_prep_readv(sqe, socket, &req->iov[0], 1, 0);
    io_uring_sqe_set_data(sqe, req);

    return 0;
}

int add_write_request(int socket) {
    struct request *req = malloc(sizeof(*req) + sizeof(struct iovec));
    req->iov[0].iov_base = malloc(READ_SIZE);
    req->iov[0].iov_len = READ_SIZE;
    req->client_socket = socket;
    memset(req->iov[0].iov_base, 0, READ_SIZE);

    struct io_uring_sqe *sqe = io_uring_get_sqe(&ring);
    req->type = WRITE;
    io_uring_prep_writev(sqe, req->client_socket, req->iov, 1, 0);
    io_uring_sqe_set_data(sqe, req);

    return 0;
}

void loop(char *host, char *port) {
    struct io_uring_cqe *cqe;
    struct sockaddr_in client_addr;
    socklen_t client_addr_len = sizeof(client_addr);

    int in_flight = 0;
    int remaining = num_ops;
    int write_count = 0;
    int read_count = 0;

    while (read_count < num_ops) {

        unsigned space = io_uring_sq_space_left(&ring);
        int queued = 0;
        while (space > 0 && remaining > 0 && in_flight < concurrent_ops) {
            int sock = client_connect(host, port);
            add_write_request(sock);
            space--;
            remaining--;
            in_flight++;
            queued++;
        }
        if (queued > 0) {
            io_uring_submit(&ring);
        }

        int ret = io_uring_wait_cqe(&ring, &cqe);
        if (ret < 0) {
            fatal_error("io_uring_wait_cqe");
        }

        struct request *req = (struct request*) cqe->user_data;
        if (cqe->res < 0) {
            fprintf(stderr, "Async request failed: %s, for event: %d on socket %d\n",
                    strerror(-cqe->res), req->type, req->client_socket);
            exit(1);
        }

        switch (req->type) {
        case ACCEPT:
            //fprintf(stderr, "Client should never reach accept\n");
            exit(1);
            break;
        case READ:
            read_count++;
            if (debug) fprintf(stderr, "READ %d\n", cqe->res);
            close(req->client_socket);
            free(req->iov[0].iov_base);
            free(req);
            in_flight--;
            break;
        case WRITE:
            write_count++;
            if (debug) fprintf(stderr, "WRITE %d\n", cqe->res);
            add_read_request(req->client_socket);
            io_uring_submit(&ring);
            free(req->iov[0].iov_base);
            free(req);
            break;
        }

        io_uring_cqe_seen(&ring, cqe);
    }
}


const char argp_program_doc[] =
    "Echo client\n"
    "\n"
    "Usage: ./client\n";

static const struct argp_option opts[] = {
    {"host", 'h', "address", 0, "Address of host"},
    {"port", 'p', "number", 0, "Port number of echo service"},
    {"times", 'n', "number", 0, "Repeat number of times"},
    {"concurrent", 'c', "number", 0, "Number of concurrent requests"},
    {"debug", 'd', 0, 0, "Provide debug output"},
    {},
};

char *host = DEFAULT_HOST;
char *port = DEFAULT_PORT;

error_t parse_opts (int key, char *arg, struct argp_state *state)
{
    switch (key) {
    case 'h':
        host = arg;
        break;
    case 'p':
        port = arg;
        break;
    case 'n':
        num_ops = atoi(arg);
        break;
    case 'c':
        concurrent_ops = atoi(arg);
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

    signal(SIGINT, signal_handler);
    io_uring_queue_init(QUEUE_DEPTH, &ring, 0);

    // Client
    loop(host, port);

    return 0;
}
