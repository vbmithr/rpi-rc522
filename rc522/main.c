#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#define __STDC_FORMAT_MACROS
#include <inttypes.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <ifaddrs.h>
#include <uuid.h>
#include <sqlite3.h>
#include <pthread.h>
#include <assert.h>

#include "base64.h"
#include "rfid.h"
#include "config.h"

const char* reader_uuid_str = "54c750dc-0ccd-4c03-90d0-c47b26d567b6";
uuid_t reader_uuid;

/* CONFIG: Misc */

int mcast_period = 1; /* cmdline configurable */
int backlog = 10;
int verbose = 0;
int daemonize = 0;

/* CONFIG: Addresses and ports */

const char* service = "3490";
const char* mcast_addr = "ff05::76:616c:6574";
int mcast_port = 5522;
int mcast_fd; /* setup by main */
struct sockaddr_in6 mcast_saddr; /* setup by main */
int i2caddr = 0x28; /* cmdline configurable */

/* SHARED STATED */

sqlite3 *db;
pthread_mutex_t db_lock;

uint32_t mcast_cnt = 0;
pthread_mutex_t mcast_lock;

/* Types */

enum msg_ctos {
    ListAccess,
    AddAccess,
    DelAccess,
    ListKeys,
    AddKey,
    DelKey
};

enum msg_stoc {
    CmdOK, // Command executed succesfully
    CmdNOK, // Command failed
    CmdEOT, // End of transmission
};

enum evtkind {
    Hello,
    UnknownKey,
    AuthInvalid,
    AccessGranted,
    AccessDenied
};

enum result {
    Ok,
    Error
};

struct access {
    uuid_t uuid;
    char descr[128];
    uint8_t cond[128];
};

struct key {
    uuid_t access;
    uint64_t uid; // max 7 bytes
    uint8_t key[12]; // two classic keys
    uint8_t secret[48]; // max size of secret
};

struct client {
    int fd;
    struct sockaddr_in6 saddr;
};

/* Implementation */

int key_row_cb(void* arg, int argc, char** argv, char** colName) {
    int fd = *((int*)arg);
    char buf[1024] = {0};
    uint8_t b64decode[1024];
    size_t dlen = 1024;
    int ret;
    uuid_t uuid;

    ret = uuid_parse(argv[1], uuid);
    if (ret == -1) {
        fprintf(stderr, "Corrupted UUID\n");
        return SQLITE_OK;
    }

    // buf+0 = CmdOk
    *((uint16_t *)buf+1) = htons(16+8+12+48);

    memcpy(buf+4, uuid, 16);
    *((uint64_t *)&buf[4+16]) = htobe64(atoll(argv[0]));

    ret = base64_decode(b64decode, &dlen, (unsigned char*) argv[2], strlen(argv[2]));
    if (ret != 0) {
        fprintf(stderr, "base64_decode error, exiting.\n");
        exit(EXIT_FAILURE);
    }
    memcpy(buf+4+16+8, b64decode, dlen);

    ret = base64_decode(b64decode, &dlen, (unsigned char*) argv[2], strlen(argv[2]));
    if (ret != 0) {
        fprintf(stderr, "base64_decode error, exiting.\n");
        exit(EXIT_FAILURE);
    }
    memcpy(buf+4+16+8+12, b64decode, dlen);

    ret = send(fd, buf, 4+16+8+12+48, 0);
    if (ret == -1)
        perror("send");

    if (ret == 4+16+8+12+48) return SQLITE_OK;
    else return ret;
}

int list_keys(int fd, uuid_t uuid) {
    char sql[1024];
    char *errmsg;
    int ret;
    char uuid_str[37];

    uuid_unparse(uuid, uuid_str);

    snprintf(sql, 1024, "select * from keys where access is '%s'", uuid_str);

    pthread_mutex_lock(&db_lock);
    ret = sqlite3_exec(db, sql, key_row_cb, &fd, &errmsg);
    if (ret != SQLITE_OK) {
        fprintf(stderr, "%s\n", errmsg);
        sqlite3_free(errmsg);
    }
    pthread_mutex_unlock(&db_lock);

    // Send an EOT message to signal the end of transmission
    *((uint16_t *)sql) = htons(CmdEOT);
    *((uint16_t *)sql+1) = htons(0);
    ret = send(fd, sql, 4, 0);

    return ret;
}

int access_row_cb(void* arg, int argc, char** argv, char** colName) {
    int fd = *((int*)arg);
    char buf[1024] = {0};
    uint8_t b64decode[1024];
    size_t dlen = 1024;
    int ret;
    uuid_t uuid;

    // Debug
    fprintf(stderr, "get %s, %s, %s\n", argv[0], argv[1], argv[2]);

    ret = uuid_parse(argv[0], uuid);
    if (ret == -1) {
        fprintf(stderr, "Corrupted UUID\n");
        return SQLITE_OK;
    }

    if (argv[2] == NULL) {
        fprintf(stderr, "Corrupted record %d\n", argc);
        return SQLITE_OK;
    }

    // buf+0 = CmdOk
    *((uint16_t *)buf+1) = htons(16+128+128);
    memcpy(buf+4, uuid, 16);

    strncpy(buf+4+16, argv[1], 128);

    ret = base64_decode(b64decode, &dlen, (unsigned char*) argv[2], strlen(argv[2]));
    if (ret != 0) {
        fprintf(stderr, "base64_decode error, exiting.\n");
        exit(EXIT_FAILURE);
    }
    memcpy(buf+4+16+128, b64decode, dlen);

    ret = send(fd, buf, 4+16+128+128, 0);
    if (ret == -1)
        perror("send");

    if (ret == 4+16+128+128) return SQLITE_OK;
    else return ret;
}

int list_accesses(int fd) {
    char sql[1024];
    char *errmsg;
    int ret;

    snprintf(sql, 1024, "select * from accesses");

    pthread_mutex_lock(&db_lock);
    ret = sqlite3_exec(db, sql, access_row_cb, &fd, &errmsg);
    if (ret != SQLITE_OK) {
        fprintf(stderr, "%s\n", errmsg);
        sqlite3_free(errmsg);
    }
    pthread_mutex_unlock(&db_lock);

    // Send an EOT message to signal the end of transmission
    *((uint16_t *)sql) = htons(CmdEOT);
    *((uint16_t *)sql+1) = htons(0);
    ret = send(fd, sql, 4, 0);

    return ret;
}

int add_access(int fd, struct access* a) {
    char sql[1024];
    uint8_t b64cond[1024] = {0};
    size_t dlen = 1024;
    char *errmsg;
    int ret;
    char uuid_str[37];

    ret = base64_encode(b64cond, &dlen, a->cond, 128);
    if (ret != 0) {
        switch(ret) {
        case POLARSSL_ERR_BASE64_BUFFER_TOO_SMALL:
            fprintf(stderr, "base64_encode buffer too small, exiting.\n");
            break;
        }
        exit(EXIT_FAILURE);
    }

    uuid_unparse(a->uuid, uuid_str);

    snprintf(sql, 1024, "insert or replace into accesses values ('%s','%s','%s')",
             uuid_str, a->descr, b64cond);
    fprintf(stderr, "%s\n", sql);

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

    *((uint16_t *)sql+1) = htons(16);
    memcpy(sql+4, reader_uuid, 16);
    send(fd, sql, 4+16, 0);

    return ret;
}

int delete_access(int fd, uuid_t uuid) {
    char sql[1024];
    char *errmsg;
    int ret;
    char uuid_str[37];

    uuid_unparse(uuid, uuid_str);

    snprintf(sql, 1024, "delete from accesses where uuid is '%s'", uuid_str);

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

int add_key(int fd, struct key* k) {
    char sql[1024];
    uint8_t key[1024] = {0};
    uint8_t secret[1024] = {0};
    char uuid_str[37];
    size_t dlen = 1024;

    char *errmsg;
    int ret;

    ret = base64_encode(key, &dlen, k->key, 12);
    fprintf(stderr, "key: %s\n", key);
    if (ret != 0) {
        switch(ret) {
        case POLARSSL_ERR_BASE64_BUFFER_TOO_SMALL:
            fprintf(stderr, "base64_encode buffer too small, exiting.\n");
            break;
        }
        exit(EXIT_FAILURE);
    }

    dlen = 1024;
    ret = base64_encode(secret, &dlen, k->secret, 48);
    fprintf(stderr, "secret: %s\n", secret);
    if (ret != 0) {
        switch(ret) {
        case POLARSSL_ERR_BASE64_BUFFER_TOO_SMALL:
            fprintf(stderr, "base64_encode buffer too small, exiting.\n");
            break;
        }
        exit(EXIT_FAILURE);
    }

    uuid_unparse(k->access, uuid_str);

    snprintf(sql, 1024, "insert or replace into keys values (%" PRIu64 ", '%s', '%s', '%s')",
             k->uid, uuid_str, key, secret);

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

int delete_key(int fd, struct key* k) {
    char sql[1024];
    char uuid_str[37];

    char *errmsg;
    int ret;

    uuid_unparse(k->access, uuid_str);

    snprintf(sql, 1024, "delete from keys where uid = %" PRIu64 " and access = '%s'",
             k->uid, uuid_str);

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
    uuid_t uuid;
    char uuid_str[37];

    switch (msg) {
    case ListAccess:
        fprintf(stderr, "ListAccess\n");
        ret = list_accesses(fd);
        break;
    case AddAccess:
        ret = read(fd, &a, size);
        fprintf(stderr, "Read %d bytes.\n", ret);
        fprintf(stderr, "AddAccess\n");
        ret = add_access(fd, &a);
        break;
    case DelAccess:
        read(fd, uuid, size);
        uuid_unparse(uuid, uuid_str);
        fprintf(stderr, "Read %d bytes.\n", ret);
        fprintf(stderr, "DelAccess %s\n", uuid_str);
        delete_access(fd, uuid);
        break;
    case ListKeys:
        ret = read(fd, uuid, size);
        fprintf(stderr, "Read %d bytes.\n", ret);
        fprintf(stderr, "ListKeys %s\n", uuid_str);
        list_keys(fd, uuid);
        break;
    case AddKey:
        ret = read(fd, &k, size);
        fprintf(stderr, "Read %d bytes.\n", ret);
        k.uid = be64toh(k.uid);
        uuid_unparse(k.access, buf);
        fprintf(stderr, "AddKey uid=0x%" PRIx64 " access_id=%s\n", k.uid, buf);
        add_key(fd, &k);
        break;
    case DelKey:
        ret = read(fd, &k, size);
        fprintf(stderr, "Read %d bytes.\n", ret);
        k.uid = be64toh(k.uid);
        uuid_unparse(k.access, buf);
        fprintf(stderr, "DelKey uid=0x%" PRIx64 " access_id=%s\n", k.uid, buf);
        delete_key(fd, &k);
        break;
    }

    close(fd);
    free(arg);
    return NULL;
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


        char ipv6[INET6_ADDRSTRLEN];
        struct in6_addr cur_addr = ((struct sockaddr_in6*)ifa->ifa_addr)->sin6_addr;
        if (family == AF_INET6
            && !IN6_IS_ADDR_LOOPBACK(&cur_addr) && !IN6_IS_ADDR_LINKLOCAL(&cur_addr)
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
    int ret;
    struct sockaddr_in6 mysaddr;
    char buf[1024] = {0};

    if (arg != NULL)
        memcpy(&mysaddr.sin6_addr, arg, sizeof(struct in6_addr));
    else {
        ret = find_ip(&mysaddr);
        if (ret != 0) {
            fprintf(stderr, "hello_t is unable to get one valid IPv6 address.\n");
            exit(EXIT_FAILURE);
        }
    }
    mysaddr.sin6_port = htons(atoi(service));

    fprintf(stderr, "Using IPv6 %s\n",
            inet_ntop(AF_INET6, &mysaddr.sin6_addr, buf, INET6_ADDRSTRLEN));

    int size = 4 /* uint32_t id */ + sizeof(uuid_t) + sizeof(struct sockaddr_in6);

    *((uint16_t*)buf) = htons(Hello);
    *((uint16_t*)buf+1) = htons(size);
    memcpy(buf+8, reader_uuid, 16);
    memcpy(buf+24, &mysaddr, sizeof(struct sockaddr_in6));

    while (1) {
        pthread_mutex_lock(&mcast_lock);
        *((uint32_t*)buf+1) = htonl(mcast_cnt);
        mcast_cnt++;
        pthread_mutex_unlock(&mcast_lock);

        ret = sendto(mcast_fd, buf, size+4, MSG_EOR,
                     (const struct sockaddr*) &mcast_saddr,
                     sizeof(struct sockaddr_in6));
        if (ret == -1)
            perror("sendto");
        sleep(mcast_period);
    }

    return NULL;
}

void* server_t(void *arg) {
    struct addrinfo hints, *res;
    int sockfd;
    int new_fd;
    int ret;
    socklen_t addr_size;

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET6;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE | AI_V4MAPPED | AI_ALL;

    ret = getaddrinfo(NULL, service, &hints, &res);
    if (ret != 0) {
        perror("getaddrinfo");
        exit(EXIT_FAILURE);
    }
    sockfd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    ret = setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &(int){ 1 }, sizeof(int));
    if (ret != 0) {
        perror("setsockopt");
        exit(EXIT_FAILURE);
    }
    inet_pton(AF_INET6, "::", &((struct sockaddr_in6*)res->ai_addr)->sin6_addr);
    ret = bind(sockfd, res->ai_addr, res->ai_addrlen);
    if (ret != 0) {
        perror("bind");
        exit(EXIT_FAILURE);
    }
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

int granted;

void* beep_t(void *arg) {
    int fd = open("/sys/class/gpio/gpio15/value", O_WRONLY);
    if (fd == -1) return NULL;

    write(fd, "1", 1);
    if (granted) usleep(200000);
    else usleep(1000000);
    write(fd, "0", 1);

    close(fd);
    return NULL;
}

int check_access_row_cb(void* arg, int argc, char** argv, char** colName) {
    uint64_t uid_db = atoll(argv[0]), uid_to_check = be64toh(*((uint64_t*)arg));

    if (uid_db == uid_to_check) granted = 1;

    return SQLITE_OK;
}

/* Check access, perform action (buzzer?) and create the appropriate
   event */
int check_access(uint8_t* SN, size_t len) {
    uint8_t uid[8] = {0};
    if (len == 4) memcpy(uid+4, SN, len);
    if (len == 7) memcpy(uid+1, SN, len);
    int ret;
    char sql[1024] = {0};
    char* errmsg;
    snprintf(sql, 1024, "select * from keys inner join accesses on keys.access = accesses.uuid");

    granted = 0;

    pthread_mutex_lock(&db_lock);
    ret = sqlite3_exec(db, sql, check_access_row_cb, uid, &errmsg);
    if (ret != SQLITE_OK) {
        fprintf(stderr, "%s\n", errmsg);
        sqlite3_free(errmsg);
    }
    pthread_mutex_unlock(&db_lock);

    pthread_t beep;
    /* Beep accordingly. */
    pthread_create(&beep, NULL, beep_t, NULL);

    /* Now send an event according to the value of granted (either
       unknown key or access granted) */
    if (granted)
        *((uint16_t*)sql) = htons(AccessGranted);
    else
        *((uint16_t*)sql) = htons(UnknownKey);
    *((uint16_t*)sql+1) = htons(20 + len);
    pthread_mutex_lock(&mcast_lock);
    *((uint32_t*)sql+1) = htonl(mcast_cnt);
    mcast_cnt++;
    pthread_mutex_unlock(&mcast_lock);
    memcpy(sql+8, reader_uuid, 16);
    memcpy(sql+24, SN, len);

    ret = sendto(mcast_fd, sql, 24+len, MSG_EOR,
                 (const struct sockaddr*) &mcast_saddr,
                 sizeof(struct sockaddr_in6));
    if (ret == -1)
        perror("sendto");

    return granted;
}

/* Loop reading RFIDs and wake up listeners when reading is
   successful. */
void* rfid_t(void *arg) {
    uint8_t SN[1024];
    uint8_t SN_len;

    uint16_t CType = 0;
    char status;

    char sn_str[23] = {0};
    int ret;
    int fd = InitRc522 ("/dev/i2c-0", i2caddr);

    if (fd == -1) {
        fprintf(stderr, "Unable to initialize RFID, exiting thread.\n");
        return NULL;
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

        // At this point we successfully read a uid
        ret = check_access(SN, SN_len);

        if (verbose) {
            for (int i = 0; i < SN_len; i++) {
                sprintf (sn_str + 2*i, "%02x", SN[i]);
            }
            fprintf (stderr, "Type: %04x, Serial: %s\n", CType, sn_str);
            fprintf (stderr, "New tag: type=%04x SNlen=%d SN=[%s]\n", CType, SN_len, sn_str);
            if (ret)
                fprintf(stderr, "Access granted!\n");
            else
                fprintf(stderr, "Access denied!\n");
        }
    }
}

int main (int argc, char *argv[]) {
    int ret;
    char db_path[256];
    struct in6_addr v6addr;
    struct in6_addr *pv6addr = NULL;

    strncpy(db_path, ".accesses.db", 256);

        /* Parse cmdline arguments */
    while ((ret = getopt (argc, argv, "vp:i:dc:6:")) != -1) {
        switch (ret) {
        case 'v':
            verbose = 1;
            break;
        case 'p':
            mcast_period = atoi(optarg);
            break;
        case 'i':
            i2caddr = atoi(optarg);
            break;
        case 'd':
            daemonize = 1;
            break;
        case 'c':
            strncpy(db_path, optarg, 256);
            break;
        case '6':
            if ((ret = inet_pton(AF_INET6, optarg, &v6addr)) == -1) {
                perror("inet_ntop");
                exit(EXIT_FAILURE);
            };
            pv6addr = &v6addr;
        }
    }

    if (daemonize) {
        if ((ret = daemon(0, 0)) == -1) {
            perror("daemon");
            exit(EXIT_FAILURE);
        }
    }

    uuid_parse(reader_uuid_str, reader_uuid);
    fprintf(stderr, "Using uuid %s\n", reader_uuid_str);

    /* Setup mcast socket  */
    mcast_saddr.sin6_family = AF_INET6;
    mcast_saddr.sin6_port = htons(mcast_port);
    inet_pton(AF_INET6, mcast_addr, &mcast_saddr.sin6_addr);
    mcast_fd = socket(AF_INET6, SOCK_DGRAM, 0);
    if (mcast_fd == -1) {
        perror("socket");
        exit(EXIT_FAILURE);
    }
    ret = setsockopt(mcast_fd, IPPROTO_IPV6, IPV6_MULTICAST_LOOP, &(int){ 1 }, sizeof(int));
    if (ret == -1) {
        perror("setsockopt");
        exit(EXIT_FAILURE);
    }


    /* Setup GPIOs */
    int fd;
    fd = open("/sys/class/gpio/export", O_WRONLY);
    if (fd == -1) {
        perror("open");
    }
    else {
        write(fd, "21", 2); /* RSTPWD */
        write(fd, "15", 2); /* Buzzer */
        close(fd);
    }

    fd = open("/sys/class/gpio/gpio21/direction", O_WRONLY);
    if (fd == -1) {
        perror("open");
    }
    else {
        write(fd, "out", 3);
        close(fd);
    }

    fd = open("/sys/class/gpio/gpio15/direction", O_WRONLY);
    if (fd == -1) {
        perror("open");
    }
    else {
        write(fd, "out", 3);
        close(fd);
    }

    fd = open("/sys/class/gpio/gpio21/value", O_WRONLY);
    if (fd == -1) {
        perror("open");
    }
    else {
        write(fd, "1", 1);
        close(fd);
    }

    ret = sqlite3_open(db_path, &db);
    if (ret) {
        fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        exit(EXIT_FAILURE);
    }

    fprintf(stderr, "Using db file %s\n", db_path);

    pthread_t srv_id, rfid_id, hello_id;
    /* Launch the server. */
    pthread_create(&srv_id, NULL, server_t, NULL);

    /* Launch the RFID reader thread */
    pthread_create(&rfid_id, NULL, rfid_t, NULL);

    /* Launch mcast hello. */
    pthread_create(&hello_id, NULL, hello_t, pv6addr);

    /* Wait for the server to finish */
    void* th_ret;
    pthread_join(srv_id, &th_ret);

    return 0;
}
