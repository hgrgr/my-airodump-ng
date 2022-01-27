#ifndef MYF
#define MYF 

#include "stdafx.h"
#include "ieee80211_header.h"
//Frame Type
#define BEACON 0x0080
#define QOS 0x0088
#define RTOS 0x00b4
#define BACK 0x0094
#define PROVRS 0x0050
#define PROVRQ 0x0040
#define DATA 0x0008
#define NULLF 0x0048
#define TYPEMASK 0x00FF
//Flags
#define FROMAP 0x0200
#define TOAP 0x0100
#define FLAGMASK 0xFF00
//LEN
#define RADIOLEN 2
#define BEACONLEN 24
#define PROVRSLEN 24
#define FIXLEN 12
#define BBSID 16
//Tag
#define RSN 48

bool pcap_print(struct BeaconFrame *buf);
int parsing(struct ParsData *pData,const u_char *buf,struct pcap_pkthdr * header);
void printAll();
void updateAP(struct ParsData pData,const u_char *tbuf,int type);
void updateSTA(struct ParsData pData, ShareFrame *buf, u_int16_t fc);
void putSta(std::array<u_int8_t,6> staMac,int num, ShareFrame * buf,int type);
bool findPara(struct ParsData pData,const u_char *buf,u_int8_t num, u_int8_t * temp);
#endif
