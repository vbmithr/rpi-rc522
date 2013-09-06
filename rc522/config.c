/*
 * config.c
 *
 *  Created on: 05.09.2013
 *      Author: alexs
 */

#include "config.h"

char config_file[]="/usr/local/etc/rc522.conf";
FILE *fdconfig;
char str[255];

int find_config_param(char * param_name, char * param_val, int val_len, int log) {
	int param_found=0;
	char * pstr;

	if ((fdconfig=fopen("/usr/local/etc/rc522.conf","r"))==NULL) return -1;

	while (fgets(str,sizeof(str)-1,fdconfig)!=NULL) {
		if ((pstr=strchr(str,'#'))!=NULL) *pstr=0; //Заменим # на конец строки.
		if ((pstr=strstr(str,param_name))!=NULL) {
			param_found=1;
			if (log) syslog(LOG_DAEMON|LOG_INFO,"Found %s",str);
			pstr+=strlen(param_name);
			while (isspace(*pstr)) pstr++;
			while (isspace(pstr[strlen(pstr)-1])) pstr[strlen(pstr)-1]=0;
			strncpy(param_val,pstr,val_len);
#if DEBUG==1
			printf("Debug:%s\n",param_val);
#endif
break;
		}
	}
	fclose(fdconfig);
	return param_found;
}

/*
if ((fdconfig=fopen("/usr/local/etc/rc522.conf","r"))!=NULL) {
	found=0;
	while (fgets(str,sizeof(str)-1,fdconfig)!=NULL) {
		if (strstr(str,sn_str)==&str[0]) {
			found=1;
			syslog(LOG_USER|LOG_INFO,"%s",str);
			//&str[strlen(sn_str)+1]
			if ((child=fork())==0) {
				execl("/bin/sh","sh","-c",&str[strlen(sn_str)+1],NULL);
			}else{
				i=1000;
				do {
					usleep(10000);
					tmp=wait3(&tmp,WNOHANG,NULL);
					i--;
				} while (i>0 && tmp!=child);

				if (tmp!=child) {
					kill(child,SIGKILL);
					wait3(&tmp,0,NULL);
					printf("Killed\n");
				}else {
					printf("Exit\n");
				}
			}
			break;
		}
	}
fclose(fdconfig);
}
*/
