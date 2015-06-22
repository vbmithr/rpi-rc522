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
#include <b64.h>

#include "rfid.h"
#include "config.h"

/* Config */

int backlog = 10;
int tcp_port = 3490;
const char* service = "3490";
const char* mcast_addr = "ff05::76:616c:6574";
int mcast_port = 5522;
uuid_t uuid;

int debug = 0;

sqlite3 *db;
pthread_mutex_t db_lock;

enum msg_ctos {
    ListAccess,
    AddAccess,
    RemoveAccess,
    ListKeys,
    AddKey,
    RemoveKey
};

enum msg_stoc {
    CmdOK, // Command executed succesfully
    CmdNOK, // Command failed
    CmdEOT, // End of transmission
};

enum result {
    Ok,
    Error
};

struct access {
    uint32_t id;
    char descr[128];
    uint8_t cond[128];
};

struct key {
    uint32_t access_id;
    uint64_t uid; // max 7 bytes
    uint8_t key[12]; // two classic keys
    uint8_t secret[48]; // max size of secret
};

struct client {
    int fd;
    struct sockaddr_in6 saddr;
};

int row_cb(void *arg, int argc, char** argv, char** colName) {
    int fd = *((int*)arg);
    char buf[1024] = {0};
    int ret;

    // buf+0 = CmdOk
    *((uint16_t *)buf+1) = htons(sizeof(struct access));
    *((uint32_t *)buf+1) = atoi(argv[0]);

    strncpy(buf+8, argv[1], 128);
    fprintf(stderr, "get %s, %s\n", argv[1], argv[2]);

    uint8_t *decoded = b64_decode(argv[2], strlen(argv[2]));
    memcpy(buf+8+128, decoded, 128);
    free(decoded);

    ret = send(fd, buf, 4+4+128+128, 0);
    if (ret == -1)
        perror("send");

    if (ret == 256+8) return SQLITE_OK;
    else return ret;
}

int list_access(int fd) {
    char sql[1024];
    char *errmsg;
    int ret;

    snprintf(sql, 1024, "select * from accesses");

    pthread_mutex_lock(&db_lock);
    ret = sqlite3_exec(db, sql, row_cb, &fd, &errmsg);
    if (ret != SQLITE_OK) {
        fprintf(stderr, "%s\n", errmsg);
        sqlite3_free(errmsg);
    }
    pthread_mutex_unlock(&db_lock);

    // Send an EOT message to signal the end of transmission
    char buf[4];
    *((uint16_t *)buf) = htons(CmdEOT);
    *((uint16_t *)buf+2) = htons(0);
    ret = send(fd, buf, 4, 0);

    return ret;
}

int add_access(int fd, struct access a) {
    char sql[1024];
    char *errmsg;
    int ret;

    char *b64cond = b64_encode(a.cond, 128);
    snprintf(sql, 1024, "insert or replace into accesses (descr,cond) values ('%s','%s')",
             a.descr, b64cond);
    fprintf(stderr, "%s\n", sql);
    free(b64cond);

    pthread_mutex_lock(&db_lock);
    ret = sqlite3_exec(db, sql, NULL, NULL, &errmsg);
    if (ret != SQLITE_OK && errmsg != NULL) {
        fprintf(stderr, "%s\n", errmsg);
        sqlite3_free(errmsg);
    }
    pthread_mutex_unlock(&db_lock);

    // Reusing now useless sql buf
    if (ret == SQLITE_OK)
        *((uint16_t *)sql) = htons(CmdOK);
    else
        *((uint16_t *)sql) = htons(CmdNOK);

    *((uint16_t *)sql+1) = htons(4);
    *((uint32_t *)sql+1) = htonl(sqlite3_last_insert_rowid(db));
    send(fd, sql, 4+4, 0);

    return ret;
}

int remove_access(int fd, int id) {
    char sql[1024];
    char *errmsg;
    int ret;

    snprintf(sql, 1024, "delete from accesses where id is %d", id);

    pthread_mutex_lock(&db_lock);
    ret = sqlite3_exec(db, sql, NULL, NULL, &errmsg);
    if (ret != SQLITE_OK && errmsg != NULL) {
        fprintf(stderr, "%s\n", errmsg);
        sqlite3_free(errmsg);
    }
    pthread_mutex_unlock(&db_lock);

    // Reusing now useless sql buf
    if (ret == SQLITE_OK)
        *((uint16_t *)sql) = htons(CmdOK);
    else
        *((uint16_t *)sql) = htons(CmdNOK);

    *((uint16_t *)sql+1) = htons(0);
    send(fd, sql, 4, 0);

    return ret;
}

int add_key(struct key k) {
    char sql[1024];
    char *errmsg;
    int ret;

    snprintf(sql, 1024, "insert or replace into keys values (%ld, %s, %s, %d)",
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
    int ret;

    char ip6[INET6_ADDRSTRLEN];
    int fd = ((struct client *) arg)->fd;
    struct sockaddr_in6 *saddr = &(((struct client *)arg)->saddr);

    inet_ntop(AF_INET6, &(saddr->sin6_addr), ip6, INET6_ADDRSTRLEN);
    fprintf(stderr, "Connection from [%s]:%d\n", ip6, ntohs(saddr->sin6_port));

    char buf[1024] = {0};
    uint16_t msg, size;
    uint16_t *p = (uint16_t *)buf;
    ret = read(fd, buf, 4);
    msg = ntohs(*p);
    size = ntohs(*(p+1));
    fprintf(stderr, "Read new message kind %d, size %d\n", msg, size);

    struct access a;
    struct key k;
    int id;

    switch (msg) {
    case ListAccess:
        fprintf(stderr, "ListAccess\n");
        ret = list_access(fd);
        break;
    case AddAccess:
        ret = read(fd, &a, size);
        fprintf(stderr, "Read %d bytes.\n", ret);
        fprintf(stderr, "AddAccess\n");
        ret = add_access(fd, a);
        break;
    case RemoveAccess:
        read(fd, &id, size);
        fprintf(stderr, "Read %d bytes.\n", ret);
        fprintf(stderr, "RemoveAccess %d\n", id);
        remove_access(fd, id);
        break;
    case AddKey:
        read(fd, &k, size);
        fprintf(stderr, "AddKey %lx\n", k.uid);
        add_key(k);
        break;
    case RemoveKey:
        read(fd, buf, size);
        fprintf(stderr, "RemoveKey %lx\n", k.uid);
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

    getaddrinfo(NULL, service, &hints, &res);
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
        /* if (family == AF_INET6) { */
        /*     char buf[INET6_ADDRSTRLEN]; */
        /*     if (inet_ntop(AF_INET6, */
        /*                     &((struct sockaddr_in6*)ifa->ifa_addr)->sin6_addr, */
        /*                   buf, INET6_ADDRSTRLEN) == NULL) */
        /*         perror("inet_ntop"); */
        /*     fprintf(stderr, "%s\n", buf); */
        /* } */

        if (family == AF_INET6
            && !IN6_IS_ADDR_LOOPBACK(&(((struct sockaddr_in6*)ifa->ifa_addr)->sin6_addr))
            && !IN6_IS_ADDR_LINKLOCAL(&(((struct sockaddr_in6*)ifa->ifa_addr)->sin6_addr))
            )
            {
                memcpy(addr, ifa->ifa_addr, sizeof(struct sockaddr_in6));
                return 0;
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
    mysaddr.sin6_port = htons(tcp_port);

    mcast_saddr.sin6_family = AF_INET6;
    mcast_saddr.sin6_port = htons(mcast_port);
    inet_pton(AF_INET6, mcast_addr, &mcast_saddr.sin6_addr);

    int loop = 1;
    ret = setsockopt(sock, IPPROTO_IPV6, IPV6_MULTICAST_LOOP, &loop, sizeof(int));
    if (ret == -1) {
        perror("setsockopt");
        exit(EXIT_FAILURE);
    }

    int size = sizeof(struct sockaddr_in6) + sizeof(uuid_t);
    uint16_t msg16 = htons(0);
    uint16_t size16 = htons(size);

    memcpy(buf, &msg16, 2);
    memcpy(buf+2, &size16, 2);
    memcpy(buf+4, uuid, 16);
    memcpy(buf+20, &mysaddr, sizeof(struct sockaddr_in6));

    while (1) {
        ret = sendto(sock, buf, size+4, MSG_EOR,
                     (const struct sockaddr*) &mcast_saddr,
                     sizeof(struct sockaddr_in6));
        if (ret == -1)
            perror("sendto");
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
    int period = 1;
    int i2caddr = 0x28;

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
    void* th_ret;
    pthread_join(hello_id, &th_ret);

    /* Exit in presence of threads. */
    pthread_exit(NULL);
}
