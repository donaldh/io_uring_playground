#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <signal.h>
#include <argp.h>

#define SERVER_PORT 3333
#define READ_SIZE   1024

void signal_handler(int sig_num) {
    printf("Exiting\n");
    exit(0);
}

void fatal_error(const char *syscall) {
    perror(syscall);
    exit(1);
}

void main_loop(int sock) {
    struct sockaddr_in client_addr;
    socklen_t client_addr_len = sizeof(client_addr);

    char buffer[READ_SIZE] = {};

    while (1) {
        int cfd = accept(sock, (struct sockaddr*)  &client_addr, &client_addr_len);
        if (cfd < 0) {
            fatal_error("accept");
        }

        int bytes;
        while ((bytes = read(cfd, buffer, READ_SIZE)) > 0) {
          write(cfd, buffer, bytes);
        }

        close(cfd);
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
    {"async", 'a', 0, 0, "submit async request"},
    {},
};

error_t parse_opts (int key, char *arg, struct argp_state *state)
{
    switch (key) {
    case 'a':
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

    int server_socket = create_listen(SERVER_PORT);

    signal(SIGINT, signal_handler);
    main_loop(server_socket);

    return 0;
}
