#include "myfunc.h"
extern std::map<std::array<u_int8_t,6>,struct ApInfo> ap_map;
extern std::map<std::array<u_int8_t,6>,struct StaInfo> sta_map;
u_int8_t cmpbroad[6] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };

bool pcap_print(const u_char *buf)
{
    for(int i=0; i < 96; i++)
    {
        if(i % 16 == 0){
            printf("\n");
            printf("%.2X ",buf[i]);
        }else if(i % 8 == 0){
            printf("\t");
            printf("%.2X ",buf[i]);
        }else{
            printf("%.2X ",buf[i]);
        }

    }
    return true;
}
bool findPara(struct ParsData pData,const u_char *buf,u_int8_t num, u_int8_t *temp){
    u_int16_t total_len = pData.total_len;
    u_int16_t start_pos = pData.rH_len + BEACONLEN + FIXLEN;
    
    for(u_int16_t start = start_pos; start < total_len;)
    {
        if(!memcmp(&buf[start],&num,1)){
            temp = new u_int8_t[buf[start + 1]];
            memcpy(temp,&buf[start + 2],buf[start + 1]);
            return true;
        }else {
            start += buf[start + 1];
        }
    }
    return false;
}
int parsing(struct ParsData *pData,const u_char *buf,struct pcap_pkthdr * header)
{
    memcpy(&pData->rH_len,&buf[RADIOLEN],2);
    memcpy(&pData->fc,&buf[pData->rH_len],2);
    memcpy(&pData->total_len,&header->len,4);
    pData->frame_len = pData->total_len - pData->rH_len;
    pData->flags = pData->fc & FLAGMASK;
    pData->fc &= TYPEMASK;
    return 0;
}

void printAll()
{
    printf("\n\n\n\n\n\n\n");
    printf("BSSID\t\t\tBeacons\t#Data\tESSID\n\n");
    for(auto it = ap_map.begin(); it != ap_map.end(); it++){
        for(int i=0; i<6; i++)
        {
            if(i != 5)
                printf("%.2X:",it->first[i]);
            else
                printf("%.2X\t",it->first[i]);
        }
        printf("%d\t",it->second.bNum);
        printf("%d\t",it->second.data);
        for(int i=0; i < it->second.id_len; i++)
        {
            printf("%c",it->second.essid[i]);
        }
        printf("\n");
    }
    printf("\n");
    printf("BSSID\t\t\tSTATION\t\t\tFrames\tProbes\n\n");

    for(auto it = sta_map.begin(); it != sta_map.end(); it++)
    {
        if(it->second.bssid_ckbit == 1)
        {
            for(int i=0; i < 6; i++)
            {
                if(i != 5)
                    printf("%.2X:",it->second.bssid[i]);
                else
                    printf("%.2X\t",it->second.bssid[i]);
             }
        }else
            printf("(not associated)\t");
        for(int i=0; i< 6; i++)
        {
            if(i != 5)
                printf("%.2X:",it->first[i]);     
            else
                printf("%.2X\t",it->first[i]);     
        }
        printf("%d\t",it->second.frameNum);
        if(it->second.essid_ckbit == 1)//print Probes
        {
            for(int i=0; i < it->second.id_len;i++)
            {
                printf("%c",it->second.essid[i]);
            }
        }
        printf("\n");
    }
}

void updateAP(struct ParsData pData,const u_char *tbuf,int type)
{
    std::array<u_int8_t,6> apMac;
    ShareFrame *buf = (ShareFrame*)&tbuf[pData.rH_len]; 
    // type check
    if(type == BEACON){//BEACON
        memcpy(apMac.begin(),buf->bf.bssId,6);
    }else if(type == QOS || type == DATA){//QOS - AP <-> STA
        if((pData.flags & FROMAP) == FROMAP){//AP -> STA
            memcpy(apMac.begin(),buf->qfas.bssId,6);
        }
        else if((pData.flags & TOAP) == TOAP){//STA -> AP
            memcpy(apMac.begin(),buf->qfsa.bssId,6);
        }
    }
    //map check
    if(ap_map.find(apMac) != ap_map.end()){
        if(type == BEACON)
            ap_map[apMac].bNum++;
        else if(type == QOS || type == DATA)
            ap_map[apMac].data++;
    }else{//first input
        struct ApInfo apinfo;
        apinfo.data = 0;
        apinfo.bNum = 0;
        if(type == BEACON){
            apinfo.bNum++;
            if(tbuf[pData.rH_len + BEACONLEN + FIXLEN +1] > 0 && tbuf[pData.rH_len + BEACONLEN + FIXLEN] == 0x00){
                apinfo.id_len = tbuf[pData.rH_len + BEACONLEN + FIXLEN +1];
                apinfo.essid = new char[apinfo.id_len];
                memcpy(apinfo.essid,&tbuf[pData.rH_len + BEACONLEN + FIXLEN + 2],apinfo.id_len);
                apinfo.essid_ckbit = 1;
            }else{
                apinfo.id_len = 0;
                apinfo.essid_ckbit = 0;
                apinfo.essid = NULL;
            }
            /*
            if(findPara(pData,tbuf,RSN,paraBuf)){//get RSN Data  
                
            }
            */
            ap_map[apMac] = apinfo;
        }else if(type == DATA){
            apinfo.data++;
            apinfo.essid_ckbit = 0;
            apinfo.id_len = 0;
            ap_map[apMac] = apinfo;
        }
    }
}

void updateSTA(struct ParsData pData, ShareFrame *buf, u_int16_t fc)
{
    struct StaInfo stainfo;
    stainfo.id_len = 0;
    std::array<u_int8_t,6> staMac;
    switch(fc)
    {
        case QOS:  
            if((pData.flags & FROMAP) == FROMAP){
                memcpy(staMac.begin(),buf->qfas.staAdd,6);                
                putSta(staMac,QOS,buf,1);
            }else if ((pData.flags & TOAP) == TOAP){
                memcpy(staMac.begin(),buf->qfsa.staAdd,6);                
                putSta(staMac,QOS,buf,2);
            }
            break;
            /*
        case RTOS:
            printf("\nHello Request to Send");
            break;
            
        case BACK:
            printf("\nHello Block Ack");
            break;
            */
/*
        case PROVRS:
            printf("\nHello Prove Response");//add essid
            memcpy(staMac.begin(),buf->pf.detAdd,6);
            putSta(staMac,PROVRS,buf);
            break;
*/
        case PROVRQ:
            memcpy(staMac.begin(),buf->pf.srcAdd,6);
            putSta(staMac,PROVRQ,buf,0);
            break;
/*
        case DATA:
            printf("\nHello DATA");
            memcpy(staMac.begin(),buf->df.staAdd,6);
            putSta(staMac,DATA,buf,0);
            break;
*/
    }
}
void putSta(std::array<u_int8_t,6> staMac,int num, ShareFrame * buf,int type){
//map check
    u_char * tbuf = (u_char *)buf; 
    if(sta_map.find(staMac) != sta_map.end()){
        if(num == QOS){
            sta_map[staMac].frameNum++;
        }else if(num == PROVRQ){
            sta_map[staMac].frameNum++;
            if(tbuf[PROVRSLEN +1] > 0 && tbuf[PROVRSLEN] == 0 && sta_map[staMac].essid_ckbit == 0){
                sta_map[staMac].id_len = tbuf[PROVRSLEN + 1];
                sta_map[staMac].essid = new char[sta_map[staMac].id_len];
                memcpy(sta_map[staMac].essid,&tbuf[PROVRSLEN + 2],sta_map[staMac].id_len);
                sta_map[staMac].essid_ckbit = 1;
            }
        }
    }else {
        struct StaInfo stainfo;
        stainfo.frameNum = 1;
        if(num == QOS && type == 2){// AP <-> STA
            memcpy(stainfo.bssid,buf->qfsa.bssId,6);         
            stainfo.bssid_ckbit = 1;
            stainfo.essid_ckbit = 0;
            stainfo.id_len = 0;
            stainfo.essid = NULL;
            sta_map[staMac] = stainfo;        
        }else if(num == PROVRQ){//STA -> AP 
            memcpy(stainfo.bssid,buf->pf.bssId ,6);
            if(!memcmp(stainfo.bssid,cmpbroad,8)){//braodcast
                stainfo.bssid_ckbit = 0;
            }else
                stainfo.bssid_ckbit = 1;
            if(tbuf[PROVRSLEN + 1] > 0 && tbuf[PROVRSLEN] == 0x00){// braodcast 
                stainfo.id_len = tbuf[PROVRSLEN + 1];
                stainfo.essid = new char[stainfo.id_len];
                memcpy(stainfo.essid,&tbuf[PROVRSLEN + 2],stainfo.id_len);
                stainfo.essid_ckbit = 1;// ssid set
            }else{// ssid len == 0
                stainfo.essid = NULL;
                stainfo.essid_ckbit = 0;
                stainfo.id_len = 0;
            }
        sta_map[staMac] = stainfo;        
        }
    }
}

