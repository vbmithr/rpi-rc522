/*
 * main.c
 *
 *
 *  Created on: 14.08.2013
 *      Author: alexs
 */
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <syslog.h>
#include <sys/wait.h>
#include <signal.h>
#include "rfid.h"
#include "bcm2835.h"
#include "config.h"

uint8_t HW_init();

int main(int argc, char *argv[]) {

	uint8_t SN[10];
	uint16_t CType=0;
	uint8_t SN_len=0;
	char status;
	int tmp,i;

	char str[255];
	char *p;
	char sn_str[23];
	pid_t child;

	//	char* argv[ARG_MAX];

	if (HW_init()) return 1; // Если не удалось инициализировать RC522 выходим.
	InitRc522();

	for (;;) {
		status= find_tag(&CType);
		if (status==MI_NOTAGERR) {
			usleep(200000);
			continue;
		}else if (status!=MI_OK) {continue;}


		//		memset(SN,0,sizeof(SN));


		p=sn_str;
		*(p++)='[';
		for (tmp=0;tmp<SN_len;tmp++) {
			sprintf(p,"%02x",SN[tmp]);
			p+=2;
		}
		*(p++)=']';
		*(p++)=0;

		//ищем SN в конфиге
		if (find_config_param(sn_str,str,sizeof(str),1)>0) {
			child=fork();
			if (child==0) {
				fclose(stdin);
				fclose(stdout);
				fclose(stderr);
				execl("/bin/sh","sh","-c",str,NULL);
			} else if (child>0) {
				i=6000;
				do {
					usleep(10000);
					tmp=wait3(NULL,WNOHANG,NULL);
					i--;
				} while (i>0 && tmp!=child);

				if (tmp!=child) {
					kill(child,SIGKILL);
					wait3(NULL,0,NULL);
#if DEBUG==1
					printf("Killed\n");
#endif
				}else {
#if DEBUG==1
					printf("Exit\n");
#endif
				}
			}else{
				syslog(LOG_DAEMON|LOG_ERR,"Can't run child process! (%s %s)\n",sn_str,str);
			}

		}else{

			syslog(LOG_DAEMON|LOG_INFO,"New tag: type=%04x SNlen=%d SN=%s\n",CType,SN_len,sn_str);

			if (1==0) {
				switch (CType) {
				case 0x4400:
					for (i=0;i<0x0f;i+=4) {
//						status=PcdRead(i,buff);
						printf("%02x -> ",i);
						if (status==MI_OK){
//							for (tmp=0;tmp<16;tmp++) {printf("%02x",buff[tmp]);}
						}else if (status==MI_ERRCRC) {
							printf("CRC Error");
						}else{
							printf("Unknown error");
						}
						printf("\n");
					}
					break;
				case 0x0400:
					break;
				default:
					break;
				}
				printf("\n");
				fflush(stdout);
			}
		}
		PcdHalt();

	}

	bcm2835_spi_end();
	bcm2835_close();
	return 0;

}


uint8_t HW_init() {
	char user[5];
	long int uid;

	if (!bcm2835_init()) {
		perror("Can't init bcm2835!\n");
		return 1;
	}
	if (getuid()==0) {
		if (find_config_param("UID=",user,sizeof(user),0)<=0) {
			perror("UID must be set!\n");
			return 1;
		}
		uid=(int)strtol(user,NULL,10);
		if (uid<100) {
			fprintf(stderr,"Invalid UID: %s\n",user);
			return 1;
		}
		setuid(uid);
	}
	bcm2835_spi_begin();
	bcm2835_spi_setBitOrder(BCM2835_SPI_BIT_ORDER_MSBFIRST);      // The default
	bcm2835_spi_setDataMode(BCM2835_SPI_MODE0);                   // The default
	bcm2835_spi_setClockDivider(BCM2835_SPI_CLOCK_DIVIDER_32); // The default
	bcm2835_spi_chipSelect(BCM2835_SPI_CS0);                      // The default
	bcm2835_spi_setChipSelectPolarity(BCM2835_SPI_CS0, LOW);      // the default
	return 0;
}

