#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <ifaddrs.h>
#include <uuid.h>
#include <sqlite3.h>
#include <pthread.h>
#include "rfid.h"
#include "config.h"


/* Config */

int backlog = 10;
const char* tcp_port = "3490";
const char* mcast_addr = "ff05::76:616c:6574";
int mcast_port = 5522;
uuid_t uuid;

int debug = 0;

sqlite3 *db;
pthread_mutex_t db_lock;

enum msg {
    AddAccess,
    RemoveAccess,
    AddKey,
    RemoveKey
};

enum result {
    Ok,
    Error
};

struct access {
    uint32_t id;
    char descr[100];
    char cond[100];
};

struct key {
    char uid[12];
    char key[128];
    char secret[128];
    uint32_t access_id;
};

struct client {
    int fd;
    struct sockaddr_in6 saddr;
};

int add_access(struct access a) {
    char sql[1024];
    char *errmsg;
    int ret;

    snprintf(sql, 1024, "insert or replace into accesses values (%d, %s, %s)",
             a.id, a.descr, a.cond);

    pthread_mutex_lock(&db_lock);
    ret = sqlite3_exec(db, sql, NULL, NULL, &errmsg);
    if (ret == SQLITE_ABORT)
        fprintf(stderr, "%s\n", errmsg);
    pthread_mutex_unlock(&db_lock);

    return ret;
}

int remove_access(int id) {
    char sql[1024];
    char *errmsg;
    int ret;

    snprintf(sql, 1024, "delete from accesses where id is %d", id);

    pthread_mutex_lock(&db_lock);
    ret = sqlite3_exec(db, sql, NULL, NULL, &errmsg);
    if (ret == SQLITE_ABORT)
        fprintf(stderr, "%s\n", errmsg);
    pthread_mutex_unlock(&db_lock);

    return ret;
}

int add_key(struct key k) {
    char sql[1024];
    char *errmsg;
    int ret;

    snprintf(sql, 1024, "insert or replace into keys values (%s, %s, %s, %d)",
             k.uid, k.key, k.secret, k.access_id);

    pthread_mutex_lock(&db_lock);
    ret = sqlite3_exec(db, sql, NULL, NULL, &errmsg);
    if (ret == SQLITE_ABORT)
        fprintf(stderr, "%s\n", errmsg);
    pthread_mutex_unlock(&db_lock);

    return ret;
}

int remove_key(char* uid) {
    char sql[1024];
    char *errmsg;
    int ret;

    snprintf(sql, 1024, "delete from keys where uid is %s", uid);

    pthread_mutex_lock(&db_lock);
    ret = sqlite3_exec(db, sql, NULL, NULL, &errmsg);
    if (ret == SQLITE_ABORT)
        fprintf(stderr, "%s\n", errmsg);
    pthread_mutex_unlock(&db_lock);

    return ret;
}

int chk_access(int uid) {
    return 0;
}

void* client_fun_t(void* arg) {
    char ip6[INET6_ADDRSTRLEN];
    int fd = ((struct client *) arg)->fd;
    struct sockaddr_in6 *saddr = &(((struct client *)arg)->saddr);

    inet_ntop(AF_INET6, &(saddr->sin6_addr), ip6, INET6_ADDRSTRLEN);
    fprintf(stderr, "Connection from [%s]:%d\n", ip6, saddr->sin6_port);

    char buf[1024] = {0};
    uint16_t msg, size;
    uint16_t *p = (uint16_t *)buf;
    read(fd, buf, 4);
    msg = ntohs(*p);
    size = ntohs(*(p+2));

    struct access a;
    struct key k;
    int id;
    uint16_t ret;

    switch (msg) {
    case AddAccess:
        read(fd, &a, size);
        fprintf(stderr, "AddAccess: %d\n", a.id);
        ret = add_access(a);
        ret = htons(ret);
        break;
    case RemoveAccess:
        read(fd, &id, size);
        fprintf(stderr, "RemoveAccess: %d\n", id);
        remove_access(id);
        break;
    case AddKey:
        read(fd, &k, size);
        fprintf(stderr, "AddAccess: ");
        for (int i = 0; i < 12; i++)
            fprintf(stderr, "%x", k.uid[i]);
        fprintf(stderr, "\n");
        add_key(k);
        break;
    case RemoveKey:
        read(fd, buf, size);
        fprintf(stderr, "RemoveAccess: ");
        for (int i = 0; i < 12; i++)
            fprintf(stderr, "%x", k.uid[i]);
        fprintf(stderr, "\n");
        remove_key(buf);
        break;
    }

    close(fd);
    free(arg);
    return NULL;
}

void* server_t(void *arg) {
    struct addrinfo hints, *res;
    int sockfd;
    int new_fd;

    socklen_t addr_size;

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET6;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE | AI_V4MAPPED | AI_ALL;

    getaddrinfo(NULL, tcp_port, &hints, &res);
    sockfd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    bind(sockfd, res->ai_addr, res->ai_addrlen);
    listen(sockfd, backlog);

    addr_size = sizeof (struct sockaddr_in6);
    struct client *p;
    pthread_t tid;

    while(1) {
        p = malloc(sizeof(struct client));
        new_fd = accept(sockfd, (struct sockaddr *)&p->saddr, &addr_size);
        p->fd = new_fd;
        pthread_create(&tid, NULL, client_fun_t, (void*) p);
    }
}

/* Find a suitable IP for communication with the rest of the world */
int find_ip(struct sockaddr_in6 *addr) {
    struct ifaddrs *ifaddr, *ifa;
    int family, s, n;
    char host[NI_MAXHOST];
    int ret;

    ret = getifaddrs(&ifaddr);
    if (ret == -1) {
        perror("getifaddrs");
        return ret;
    }

    for (ifa = ifaddr, n = 0; ifa != NULL; ifa = ifa->ifa_next, n++) {
        if (ifa->ifa_addr == NULL)
            continue;

        family = ifa->ifa_addr->sa_family;
        if (family == AF_INET6) {
            if IN6_IS_ADDR_LINKLOCAL(&(((struct sockaddr_in6*)ifa->ifa_addr)->sin6_addr)) {
                    memcpy(addr, ifa->ifa_addr, sizeof(struct sockaddr_in6));
                    return 0;
                }
        }
    }

    freeifaddrs(ifaddr);
    return 1;
}

/* Say hello on the wire every n seconds */
void* hello_t(void* arg) {
    int sock, ret;
    int period = *((int *)arg);
    struct sockaddr_in6 mcast_saddr = {0};
    struct sockaddr_in6 mysaddr;
    uint16_t msg = htons(0), size = htons(sizeof(struct sockaddr_in6) + sizeof(uuid_t));
    char buf[1024] = {0};

    sock = socket(AF_INET6, SOCK_DGRAM, 0);
    if (sock == -1) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    ret = find_ip(&mysaddr);
    if (ret != 0) {
        fprintf(stderr, "hello_t is unable to get one valid IPv6 address.\n");
        exit(EXIT_FAILURE);
    }

    mcast_saddr.sin6_family = AF_INET6;
    mcast_saddr.sin6_port = htons(mcast_port);
    inet_pton(AF_INET6, mcast_addr, &(mcast_saddr.sin6_addr));

    memcpy(buf, &msg, 2);
    memcpy(buf+2, &size, 2);
    memcpy(buf+4, uuid, 16);
    memcpy(buf+20, &mysaddr, sizeof(struct sockaddr_in6));

    while (1) {
        sendto(sock, buf, size+4, MSG_EOR, (const struct sockaddr*) &mcast_addr, size);
        sleep(period);
    }

    return NULL;
}

/* Loop reading RFIDs and wake up listeners when reading is
   successful. */
void* rfid_t(void *arg) {
    uint8_t SN[1024];
    uint8_t SN_len;

    uint16_t CType = 0;
    int i2caddr = *((int*)(arg));
    char status;

    char *p;
    char sn_str[23];

    int fd = InitRc522 ("/dev/i2c-0", i2caddr);

    if (fd == -1) {
        fprintf(stderr, "Unable to initialize RFID, exiting thread.\n");
        pthread_exit(NULL);
    }

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
}

int main (int argc, char *argv[]) {
    int ret;
    int period = 5;
    int i2caddr = 0x30;

    /* Generate random uuid */
    uuid_generate(uuid);

    /* Parse cmdline arguments */
    while ((ret = getopt (argc, argv, "dpi:")) != -1) {
        switch (ret) {
        case 'd':
            debug = 1;
            break;
        case 'p':
            period = atoi(optarg);
            break;
        case 'i':
            i2caddr = atoi(optarg);
            break;
        }
    }

    /* Open DB for everyone */
    ret = sqlite3_open(".accesses.db", &db);
    if (ret) {
        fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        return EXIT_FAILURE;
    }

    pthread_t srv_id, hello_id, rfid_id;
    /* Launch the server. */
    pthread_create(&srv_id, NULL, server_t, NULL);

    /* Launch the RFID reader thread */
    pthread_create(&rfid_id, NULL, rfid_t, &i2caddr);

    /* Launch mcast hello */
    pthread_create(&hello_id, NULL, hello_t, (void*) &period);

    /* Wait for the server to finish */
    void* srv_ret;
    pthread_join(srv_id, &srv_ret);

    /* Exit in presence of threads. */
    pthread_exit(NULL);
}
