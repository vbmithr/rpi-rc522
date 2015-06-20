#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <linux/types.h>
#include <linux/i2c.h>
#include <linux/i2c-dev.h>
#include "rc522.h"

int main(int argc, char** argv) {
    char buf[1024] = {0};
    uint8_t reg = VersionReg, expected;
    int fd = open("/dev/i2c-0", O_RDWR);
    int ret;

    if (fd < 0) {
        perror("open");
        exit(EXIT_FAILURE);
    }

    /* for (int i = 0; i < 128; i++) { */
    /*     struct i2c_msg msgs[2] = {0}; */
    /*     msgs[0].addr = i; */
    /*     msgs[0].len = 1; */
    /*     msgs[0].buf = &reg; */
    /*     msgs[1].addr = i; */
    /*     msgs[1].flags |= I2C_M_RD; */
    /*     msgs[1].len = 1; */
    /*     msgs[1].buf = &expected; */

    /*     struct i2c_rdwr_ioctl_data msgset; */
    /*     msgset.msgs = msgs; */
    /*     msgset.nmsgs = 2; */

    /*     ret = ioctl(fd, I2C_RDWR, &msgset); */
    /*     if (ret == -1) { */
    /*         fprintf(stderr, "%02x %s\n", i, strerror(errno)); */
    /*     } */
    /*     else */
    /*         fprintf(stderr, "%02x OK\n", i); */
    /*     usleep(10000); */
    /* } */


    if (ioctl(fd, I2C_SLAVE, 0x28) < 0) {
        perror("I2C_SLAVE");
        exit(EXIT_FAILURE);
    }

    ret = write(fd, &reg, 1);
    if (ret != 1) {
        perror("write");
    }

    ret = read(fd, buf, 1);
    if (ret != 1) {
        perror("read");
    }
    uint8_t v = buf[0];
    printf("%02x\n", v);

    return EXIT_SUCCESS;
}
