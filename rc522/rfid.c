/*
 * rfid.c
 *
 *  Created on: 06.09.2013
 *      Author: alexs
 */
#include "rfid.h"



uint8_t buff[MAXRLEN];


char find_tag(uint16_t * card_type) {
	char tmp;
	if ((tmp=PcdRequest(PICC_REQIDL,buff))==MI_OK) {
		*card_type=(int)(buff[0]<<8|buff[1]);
	}
	return tmp;
}

char select_tag_sn(uint8_t * sn, uint8_t * len){

	if (PcdAnticoll(PICC_ANTICOLL1,buff)!=MI_OK) return MI_ERR;
	if (PcdSelect(PICC_ANTICOLL1,buff)!=MI_OK) return MI_ERR;
	if (buff[0]==0x88) {
		memcpy(sn,&buff[1],3);
		if (PcdAnticoll(PICC_ANTICOLL2,buff)!=MI_OK) return MI_ERR;
		if (PcdSelect(PICC_ANTICOLL2,buff)!=MI_OK) return MI_ERR;
		if (buff[0]==0x88) {
			memcpy(sn+3,&buff[1],3);
			if (PcdAnticoll(PICC_ANTICOLL3,buff)!=MI_OK) return MI_ERR;
			if (PcdSelect(PICC_ANTICOLL3,buff)!=MI_OK) return MI_ERR;
			memcpy(sn+6,buff,4);
			*len=10;
		}else{
			memcpy(sn+3,buff,4);
			*len=7;
		}
	}else{
		memcpy(sn,&buff[0],4);
		*len=4;
		return MI_OK;
	}

}


/*
if (PcdAnticoll(PICC_ANTICOLL1,buff)!=MI_OK) continue;
*/
