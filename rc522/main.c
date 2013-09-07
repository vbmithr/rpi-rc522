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

	uid_t uid;
	uint8_t SN[10];
	uint16_t CType=0;
	uint8_t SN_len=0;
	char status;
	int tmp,i;

	char str[255];
	char *p;
	char sn_str[23];
	pid_t child;
	int max_page=0;
	uint8_t page_step=0;

	FILE * fmem_str;
	char save_mem=0;
	char fmem_path[255];

	if (open_config_file(config_file)!=0) {
		syslog(LOG_DAEMON|LOG_ERR,"Can't open config file!");
		return 1;
	}

	if (HW_init()) return 1; // Если не удалось инициализировать RC522 выходим.
	if (read_conf_uid(&uid)!=0) return 1;
	setuid(uid);
	InitRc522();

	if (find_config_param("NEW_TAG_PATH=",fmem_path,sizeof(fmem_path)-1,0)) {
		save_mem=1;
		if (fmem_path[strlen(fmem_path)-1]!='/') {
			sprintf(&fmem_path[strlen(fmem_path)],"/");
			if (strlen(fmem_path)>=240) {
				perror("Too long path for tag dump files!");
				return 1;
			}
		}
#if DEBUG==1
		printf("Debug Path: %s\n",fmem_path);
#endif
	}

	for (;;) {
		status= find_tag(&CType);
		if (status==TAG_NOTAG) {
			usleep(200000);
			continue;
		}else if (status!=TAG_OK) {continue;}

		if (select_tag_sn(SN,&SN_len)!=TAG_OK) {continue;}

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
				freopen("","w",stdout);
				freopen("","w",stderr);
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

			if (save_mem) {
				switch (CType) {
				case 0x4400:
					max_page=0x0f;
					page_step=4;
					break;
				case 0x0400:
					PcdHalt();
					continue;
					max_page=0x3f;
					page_step=1;
					break;
				default:
					break;
				}
				p=str;
				sprintf(p,"%s",fmem_path);
				p+=strlen(p);
				for (tmp=0;tmp<SN_len;tmp++) {
					sprintf(p,"%02x",SN[tmp]);
					p+=2;
				}
				sprintf(p,".txt");
				if ((fmem_str=fopen(str,"r"))!=NULL) {
					fclose(fmem_str);
					PcdHalt();
					continue;
				}
				if ((fmem_str=fopen(str,"w"))==NULL) {
					syslog(LOG_DAEMON|LOG_ERR,"Cant open file for write: %s",str);
					PcdHalt();
					continue;
				}
				for (i=0;i<max_page;i+=page_step) {
					read_tag_str(i,str);
					fprintf(fmem_str,"%02x: %s\n",i,str);
				}
				fclose(fmem_str);
			}
		}
		PcdHalt();

	}

	bcm2835_spi_end();
	bcm2835_close();
	close_config_file();
	return 0;

}


uint8_t HW_init() {
	if (!bcm2835_init()) {
		syslog(LOG_DAEMON|LOG_ERR,"Can't init bcm2835!\n");
		return 1;
	}
	bcm2835_spi_begin();
	bcm2835_spi_setBitOrder(BCM2835_SPI_BIT_ORDER_MSBFIRST);      // The default
	bcm2835_spi_setDataMode(BCM2835_SPI_MODE0);                   // The default
	bcm2835_spi_setClockDivider(BCM2835_SPI_CLOCK_DIVIDER_32); // The default
	bcm2835_spi_chipSelect(BCM2835_SPI_CS0);                      // The default
	bcm2835_spi_setChipSelectPolarity(BCM2835_SPI_CS0, LOW);      // the default
	return 0;
}

