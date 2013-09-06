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


char find_tag(uint16_t *);

#endif /* RFID_H_ */
