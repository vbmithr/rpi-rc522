#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <linux/types.h>
#include <linux/i2c-dev.h>
#include "rc522.h"
#include "main.h"

static int fd;

int InitRc522(const char* i2cdev, int addr)
{
    int ret;
    int fd = open(i2cdev, O_RDWR);

    if (fd == -1) {
        perror("InitRC522");
        return -1;
    }

    ret = ioctl(fd, I2C_SLAVE, addr);
    if (ret < 0) {
        /* ERROR HANDLING; you can check errno to see what went wrong */
        perror("InitRC522");
        return ret;
    }

    PcdReset(fd);
    PcdAntennaOn(fd);
    return fd;
}

char PcdRequest(int fd, uint8_t req_code,uint8_t *pTagType)
{
	char   status;
	uint8_t   unLen;
	uint8_t   ucComMF522Buf[MAXRLEN];

	WriteRawRC(fd, BitFramingReg, 0x07);
	ucComMF522Buf[0] = req_code;

	status = PcdComMF522(fd, PCD_TRANSCEIVE,ucComMF522Buf,1,ucComMF522Buf,&unLen);
	if ((status == TAG_OK) && (unLen == 0x10))
	{
		*pTagType     = ucComMF522Buf[0];
		*(pTagType+1) = ucComMF522Buf[1];
	}
	else if (status == TAG_COLLISION) {
//		printf("ATQA %02x%02x\n",ucComMF522Buf[0],ucComMF522Buf[1]);
	}
	else if (status!=TAG_NOTAG) {
		status = TAG_ERR;
	}

	return status;
}

char PcdAnticoll(int fd, uint8_t cascade, uint8_t *pSnr)
{
	char   status;
	uint8_t   i,snr_check=0;
	uint8_t   unLen;
	uint8_t   ucComMF522Buf[MAXRLEN];
	uint8_t   pass=32;
	uint8_t	  collbits=0;

	i=0;
	WriteRawRC(fd, BitFramingReg,0x00);
	do {
		ucComMF522Buf[0] = cascade;
		ucComMF522Buf[1] = 0x20+collbits;
		//	WriteRawRC(0x0e,0);
		status = PcdComMF522(fd, PCD_TRANSCEIVE,ucComMF522Buf,2+i,ucComMF522Buf,&unLen);
		if (status == TAG_COLLISION) {
                    ReadRawRC(fd, &collbits, CollReg);
                    collbits &= 0x1f;
			if (collbits==0) collbits=32;
			i=(collbits-1)/8 +1;
//			printf ("--- %02x %02x %02x %02x %d\n",ucComMF522Buf[0],ucComMF522Buf[1],ucComMF522Buf[2],ucComMF522Buf[3],unLen);
			ucComMF522Buf[i-1]|=(1<<((collbits-1)%8));
			ucComMF522Buf[5]=ucComMF522Buf[3];
			ucComMF522Buf[4]=ucComMF522Buf[2];
			ucComMF522Buf[3]=ucComMF522Buf[1];
			ucComMF522Buf[2]=ucComMF522Buf[0];
			WriteRawRC(fd, BitFramingReg, (collbits % 8));
//			printf (" %d %d %02x %d\n",collbits,i,ucComMF522Buf[i+1],collbits % 8);
		}
	} while (((--pass)>0)&&(status==TAG_COLLISION));

	if (status == TAG_OK)
	{
		for (i=0; i<4; i++)
		{
			*(pSnr+i)  = ucComMF522Buf[i];
			snr_check ^= ucComMF522Buf[i];
		}
		if (snr_check != ucComMF522Buf[i])
		{   status = TAG_ERR;    }
	}

	return status;
}

char PcdSelect(int fd, uint8_t cascade, uint8_t *pSnr)
{
	char   status;
	uint8_t   i;
	uint8_t   unLen;
	uint8_t   ucComMF522Buf[MAXRLEN];

	ucComMF522Buf[0] = cascade;
	ucComMF522Buf[1] = 0x70;
	ucComMF522Buf[6] = 0;
	for (i=0; i<4; i++)
	{
		ucComMF522Buf[i+2] = *(pSnr+i);
		ucComMF522Buf[6]  ^= *(pSnr+i);
	}
	CalulateCRC(fd, ucComMF522Buf,7,&ucComMF522Buf[7]);

	ClearBitMask(fd, Status2Reg, 0x08);

	status = PcdComMF522(fd, PCD_TRANSCEIVE,ucComMF522Buf,9,ucComMF522Buf,&unLen);

	if ((status == TAG_OK) && (unLen == 0x18))
	{   status = TAG_OK;  }
	else
	{   status = TAG_ERR;    }

	return status;
}

char PcdAuthState(int fd, uint8_t   auth_mode,uint8_t   addr,uint8_t *pKey,uint8_t *pSnr)
{
	char   status;
	uint8_t   unLen;
	uint8_t   ucComMF522Buf[MAXRLEN];

	ucComMF522Buf[0] = auth_mode;
	ucComMF522Buf[1] = addr;
	memcpy(&ucComMF522Buf[2], pKey, 6);
	memcpy(&ucComMF522Buf[8], pSnr, 4);

	status = PcdComMF522(fd, PCD_AUTHENT,ucComMF522Buf,12,ucComMF522Buf,&unLen);
        uint8_t ret;
        ReadRawRC(fd, &ret, Status2Reg);
	if ((status != TAG_OK) || (!(ret & 0x08)))
	{   status = TAG_ERR;   }

	return status;
}

char PcdRead(int fd, uint8_t addr,uint8_t *p )
{
	char   status;
	uint8_t   unLen;
	uint8_t   i,ucComMF522Buf[MAXRLEN];
	uint8_t   CRC_buff[2];

	memset(ucComMF522Buf,0,sizeof(ucComMF522Buf));
	ucComMF522Buf[0] = PICC_READ;
	ucComMF522Buf[1] = addr;
	CalulateCRC(fd, ucComMF522Buf,2,&ucComMF522Buf[2]);

	status = PcdComMF522(fd, PCD_TRANSCEIVE,ucComMF522Buf,4,ucComMF522Buf,&unLen);
	CalulateCRC(fd, ucComMF522Buf,16,CRC_buff);
	//	printf("debug %02x%02x %02x%02x   ",ucComMF522Buf[16],ucComMF522Buf[17],CRC_buff[0],CRC_buff[1]);

	if ((status == TAG_OK) && (unLen == 0x90))
	{
		if ((CRC_buff[0]!=ucComMF522Buf[16])||(CRC_buff[1]!=ucComMF522Buf[17])) { status = TAG_ERRCRC; }
		for (i=0; i<16; i++)
		{    *(p +i) = ucComMF522Buf[i];   }
	}
	else
	{   status = TAG_ERR;   }

	return status;
}

char PcdWrite(int fd, uint8_t   addr,uint8_t *p )
{
	char   status;
	uint8_t   unLen;
	uint8_t   i,ucComMF522Buf[MAXRLEN];

	ucComMF522Buf[0] = PICC_WRITE;
	ucComMF522Buf[1] = addr;
	CalulateCRC(fd, ucComMF522Buf,2,&ucComMF522Buf[2]);

	status = PcdComMF522(fd, PCD_TRANSCEIVE,ucComMF522Buf,4,ucComMF522Buf,&unLen);

	if ((status != TAG_OK) || (unLen != 4) || ((ucComMF522Buf[0] & 0x0F) != 0x0A))
	{   status = TAG_ERR;   }

	if (status == TAG_OK)
	{
		for (i=0; i<16; i++)
		{
			ucComMF522Buf[i] = *(p +i);
		}
		CalulateCRC(fd, ucComMF522Buf,16,&ucComMF522Buf[16]);

		status = PcdComMF522(fd, PCD_TRANSCEIVE,ucComMF522Buf,18,ucComMF522Buf,&unLen);
		if ((status != TAG_OK) || (unLen != 4) || ((ucComMF522Buf[0] & 0x0F) != 0x0A))
		{   status = TAG_ERR;   }
	}

	return status;
}

char PcdHalt(int fd)
{
	uint8_t status;
	uint8_t unLen;
	uint8_t ucComMF522Buf[MAXRLEN];

	ucComMF522Buf[0] = PICC_HALT;
	ucComMF522Buf[1] = 0;
	CalulateCRC(fd, ucComMF522Buf,2,&ucComMF522Buf[2]);

	status = PcdComMF522(fd, PCD_TRANSCEIVE,ucComMF522Buf,4,ucComMF522Buf,&unLen);

	return status;
}

void CalulateCRC(int fd, uint8_t *pIn ,uint8_t   len,uint8_t *pOut )
{
	uint8_t   i,n;
	ClearBitMask(fd, DivIrqReg,0x04);
	WriteRawRC(fd, CommandReg,PCD_IDLE);
	SetBitMask(fd, FIFOLevelReg,0x80);
	for (i=0; i<len; i++)
            WriteRawRC(fd, FIFODataReg, *(pIn +i));
	WriteRawRC(fd, CommandReg, PCD_CALCCRC);
	i = 0xFF;
	do
	{
            ReadRawRC(fd, &n, DivIrqReg);
		i--;
	}
	while ((i!=0) && !(n&0x04));
	ReadRawRC(fd, pOut, CRCResultRegL);
	ReadRawRC(fd, pOut + 1, CRCResultRegM);
}

char PcdReset(int fd)
{
    WriteRawRC(fd, CommandReg,PCD_RESETPHASE);
	usleep(10000);
	ClearBitMask(fd, TxControlReg,0x03);
	usleep(10000);
	SetBitMask(fd, TxControlReg,0x03);
	WriteRawRC(fd, TModeReg,0x8D);
	WriteRawRC(fd, TPrescalerReg,0x3E);
	WriteRawRC(fd, TReloadRegL,30);
	WriteRawRC(fd, TReloadRegH,0);
	WriteRawRC(fd, TxASKReg,0x40);
	WriteRawRC(fd, ModeReg,0x3D);            //6363
	//	WriteRawRC(DivlEnReg,0x90);
	WriteRawRC(fd, RxThresholdReg,0x84);
	WriteRawRC(fd, RFCfgReg,0x68);
	WriteRawRC(fd, GsNReg,0xff);
	WriteRawRC(fd, CWGsCfgReg,0x2f);
	//	WriteRawRC(ModWidthReg,0x2f);

	return TAG_OK;
}

/*
char M500PcdConfigISOType(uint8_t   type)
{
	if (type == 'A')
	{
		ClearBitMask(Status2Reg,0x08);
		WriteRawRC(ModeReg,0x3D);
		WriteRawRC(RxSelReg,0x86);
		WriteRawRC(RFCfgReg,0x7F);
		WriteRawRC(TReloadRegL,30);
		WriteRawRC(TReloadRegH,0);
		WriteRawRC(TModeReg,0x8D);
		WriteRawRC(TPrescalerReg,0x3E);
		PcdAntennaOn();
	}
	else{ return 1; }

	return TAG_OK;
}
 */

int ReadRawRC(int fd, uint8_t *dst, uint8_t addr)
{
    int ret;
    ret = write(fd, &addr, 1);
    if (ret == -1) return ret;

    ret = read(fd, dst, 1);
    return ret;
}

int WriteRawRC(int fd, uint8_t addr, uint8_t value)
{
    uint8_t buf[2];

    buf[0] = addr;
    buf[1] = value;
    return write(fd, buf, 2);
}

int SetBitMask(int fd, uint8_t   reg,uint8_t   mask)
{
    uint8_t tmp = 0x0;
    ReadRawRC(fd, &tmp, reg);
    return WriteRawRC(fd, reg, tmp | mask);  // set bit mask
}

int ClearBitMask(int fd, uint8_t   reg,uint8_t   mask)
{
    uint8_t tmp = 0x0;
    ReadRawRC(fd, &tmp, reg);
    return WriteRawRC(fd, reg, tmp & ~mask);  // clear bit mask
}

char PcdComMF522(int fd,
                 uint8_t   Command,
		uint8_t *pIn ,
		uint8_t   InLenByte,
		uint8_t *pOut ,
		uint8_t *pOutLenBit)
{
	char   status = TAG_ERR;
	uint8_t   irqEn   = 0x00;
	uint8_t   waitFor = 0x00;
	uint8_t   lastBits;
	uint8_t   n;
	uint32_t   i;
	uint8_t PcdErr;

	//	printf("CMD %02x\n",pIn[0]);
	switch (Command)
	{
	case PCD_AUTHENT:
		irqEn   = 0x12;
		waitFor = 0x10;
		break;
	case PCD_TRANSCEIVE:
		irqEn   = 0x77;
		waitFor = 0x30;
		break;
	default:
		break;
	}

	WriteRawRC(fd, ComIEnReg, irqEn | 0x80);
	//	WriteRawRC(ComIEnReg,irqEn);
	ClearBitMask(fd, ComIrqReg,0x80);
	SetBitMask(fd, FIFOLevelReg,0x80);
	WriteRawRC(fd, CommandReg,PCD_IDLE);

	for (i=0; i<InLenByte; i++) {
            WriteRawRC(fd, FIFODataReg, pIn [i]);
	}

	WriteRawRC(fd, CommandReg, Command);

	if (Command == PCD_TRANSCEIVE) {
            SetBitMask(fd, BitFramingReg,0x80);
	}

	//i = 600;//���ʱ��Ƶ�ʵ������M1�����ȴ�ʱ��25ms
	i = 150;
	do
	{
		usleep(200);
		//		bcm2835_delayMicroseconds(200);
		ReadRawRC(fd, &n, ComIrqReg);
		i--;
	}
	while ((i!=0) && (!(n&0x01)) && (!(n&waitFor)));

	ClearBitMask(fd, BitFramingReg,0x80);

	if (i!=0)
	{
            ReadRawRC(fd, &PcdErr, ErrorReg);
		if (!(PcdErr & 0x11))
		{
			status = TAG_OK;
			if (n & irqEn & 0x01) {status = TAG_NOTAG;}
			if (Command == PCD_TRANSCEIVE) {
                            ReadRawRC(fd, &n, FIFOLevelReg);
                            ReadRawRC(fd, &lastBits, ControlReg);
                            lastBits &= 0x07;
				if (lastBits) {*pOutLenBit = (n-1)*8 + lastBits;}
				else {*pOutLenBit = n*8;}

				if (n == 0) {n = 1;}
				if (n > MAXRLEN) {n = MAXRLEN;}

				for (i=0; i<n; i++) {
                                    ReadRawRC(fd, pOut + i, FIFODataReg);
//					printf (".%02X ",pOut[i]);
				}
			}
		}
		else {
			//			fprintf (stderr,"Err %02x\n",PcdErr);
			status = TAG_ERR;}

		if (PcdErr&0x08) {
			/* if (debug) fprintf (stderr,"COllision \n"); */
			status = TAG_COLLISION;

		}

	}


	//    SetBitMask(ControlReg,0x80);           // stop timer now
	//    WriteRawRC(CommandReg,PCD_IDLE); ???????
//	printf ("PCD Err %02x\n",PcdErr);
	return status;
}

void PcdAntennaOn(int fd)
{
	uint8_t   i;
	ReadRawRC(fd, &i, TxControlReg);
	if (!(i & 0x03))
	{
            SetBitMask(fd, TxControlReg, 0x03);
	}
}

void PcdAntennaOff(int fd)
{
    ClearBitMask(fd, TxControlReg, 0x03);
}
