#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <netdb.h>
#include <argp.h>
#include <signal.h>
#include <fcntl.h>

#define SERVER_PORT 3333
#define READ_SIZE   1024

#define DEFAULT_HOST "127.0.0.1";
#define DEFAULT_PORT "3333";

int num_ops = 10;

void signal_handler(int sig_num) {
    printf("Exiting\n");
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
        //print_addr(rp);

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

void loop(char *host, char *port) {
    struct sockaddr_in client_addr;
    socklen_t client_addr_len = sizeof(client_addr);

    int read_count = 0;

    char buffer[READ_SIZE] = { 'Z' };

    while (read_count < num_ops) {
        int sock = client_connect(host, port);

        int status = fcntl(sock, F_SETFL, fcntl(sock, F_GETFL, 0) | O_NONBLOCK);
        if (status == -1){
            perror("calling fcntl");

        }
        int bytes = write(sock, buffer, READ_SIZE);
        if (bytes < 0) {
            perror("write");
            close(sock);
            read_count += 1;
            continue;
        }

        while (1) {
            bytes = read(sock, buffer, READ_SIZE);
            if (bytes < 0) {
              if (errno == EAGAIN) {
                continue;
              } else {
                perror("read");
                break;
              }
            } else if (bytes == 0) {
              break;
            }
        }

        close(sock);
        read_count += 1;
    }
}


const char argp_program_doc[] =
    "echo client\n"
    "\n"
    "Usage: client\n";

static const struct argp_option opts[] = {
    {"host", 'h', "address", 0, "address of host"},
    {"port", 'p', "number", 0, "port of echo service"},
    {"times", 'n', "number", 0, "number of times"},
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

    // Client
    loop(host, port);

    return 0;
}
