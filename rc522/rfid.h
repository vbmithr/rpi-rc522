/*
 * rfid.h
 *
 *  Created on: 06.09.2013
 *      Author: alexs
 */

#ifndef RFID_H_
#define RFID_H_

#include <string.h>
#include "rc522.h"
#include <stdint.h>
#include <stdio.h>


tag_stat find_tag(int fd, uint16_t *);
tag_stat select_tag_sn(int fd, uint8_t * sn, uint8_t * len);
tag_stat read_tag_str(int fd, uint8_t addr, char * str);

#endif /* RFID_H_ */
