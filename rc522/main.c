#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <sqlite3.h>
#include "rfid.h"
#include "config.h"

#define BACKLOG 10
#define PORT "3490"

int debug = 0;
sqlite3 *db;

int establish_tcp_server() {
    struct addrinfo hints, *res;
    int sockfd;
    /* int new_fd; */

    /* struct sockaddr_storage their_addr; */
    /* socklen_t addr_size; */

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;  // use IPv4 or IPv6, whichever
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;     // fill in my IP for me

    getaddrinfo(NULL, PORT, &hints, &res);
    sockfd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    bind(sockfd, res->ai_addr, res->ai_addrlen);
    listen(sockfd, BACKLOG);

    /* addr_size = sizeof their_addr; */
    /* new_fd = accept(sockfd, (struct sockaddr *)&their_addr, &addr_size); */

    return 0;
}

int main (int argc, char *argv[]) {
    uint8_t SN[1024];
    uint8_t SN_len;

    uint16_t CType = 0;
    char status;

    char *p;
    char sn_str[23];

    int ret;

    while ((ret = getopt (argc, argv, "d")) != -1) {
        switch (ret) {
        case 'd':
            debug = 1;
            break;
        }
    }

    ret = sqlite3_open(".accesses.db", &db);
    if (ret) {
        fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        return EXIT_FAILURE;
    }

    int fd = InitRc522 ("/dev/spidev1.0");

    for (;;) {
        status = find_tag (fd, &CType);
        if (status == TAG_NOTAG) {
            usleep (200000);
            continue;
        }
        else if ((status != TAG_OK) && (status != TAG_COLLISION))
            continue;

        if (select_tag_sn (fd, SN, &SN_len) != TAG_OK)
            continue;

        p = sn_str;
        *(p++) = '[';

        for (int i = 0; i < SN_len; i++) {
            sprintf (p, "%02x", SN[i]);
            p += 2;
        }

        //for debugging
        if (debug) {
            *p = 0;
            fprintf (stderr, "Type: %04x, Serial: %s\n", CType, &sn_str[1]);
        }
        *(p++) = ']';
        *(p++) = 0;

        if (debug)
            fprintf (stderr, "New tag: type=%04x SNlen=%d SN=%s\n", CType, SN_len, sn_str);
    }
    PcdHalt (fd);
    return EXIT_SUCCESS;
}
