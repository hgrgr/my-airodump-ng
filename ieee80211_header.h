#ifndef IEEE
#define IEEE

#include "stdafx.h"
struct ParsData{
    u_int16_t rH_len;
    u_int16_t fc;
    u_int16_t flags;
    u_int8_t apMac[6];
    u_int32_t total_len;
    u_int16_t frame_len; 
};
struct Present{
    u_int32_t word_1;
    u_int32_t word_2;
    u_int32_t word_3;
}__attribute__((packed));

struct RadioHeader{
    u_int8_t it_version;
    u_int8_t it_pad;
    u_int16_t it_len;
    struct Present pt;
    u_int64_t timeStamp; 
    u_int8_t flags;
    u_int8_t dataRate;
    u_int16_t channelFreq;
    u_int16_t channelFlags;
    u_int8_t antennaSignal;
    u_int8_t emp;
    u_int16_t rxFlags;
    u_int8_t emp2[6];
    u_int8_t timestampInfo[12];
    u_int8_t antennaSignal2;
    u_int8_t antenna2;
    u_int8_t antennaSignal3;
    u_int8_t antenna3;
} __attribute__((packed));

struct BeaconFrame{
//    struct RadioHeader rHeader;
    u_int16_t fc;//Frame Control
    u_int16_t duration;
    u_int8_t detAdd[6];
    u_int8_t srcAdd[6];
    u_int8_t bssId[6];
    u_int16_t seqNum;//Fragment Num(4) + Seq Num(12)
    //IEEE 80211 Mangment Field
}__attribute__((packed));

struct QosFrameStoA{
//    struct RadioHeader rHeader;
    u_int16_t fc;//Frame Control
    u_int16_t duration;
    u_int8_t bssId[6];
    u_int8_t staAdd[6];
    u_int8_t destAdd[6];
    u_int16_t seqNum;//Fragment Num(4) + Seq Num(12)
    //IEEE 80211 Mangment Field
}__attribute__((packed));

struct QosFrameAtoS{
//    struct RadioHeader rHeader;
    u_int16_t fc;//Frame Control
    u_int16_t duration;
    u_int8_t staAdd[6];
    u_int8_t bssId[6];
    u_int8_t srcAdd[6];
    u_int16_t seqNum;//Fragment Num(4) + Seq Num(12)
    //IEEE 80211 Mangment Field
}__attribute__((packed));

struct ProbFrame{
//    struct RadioHeader rHeader;
    u_int16_t fc;//Frame Control
    u_int16_t duration;
    u_int8_t detAdd[6];
    u_int8_t srcAdd[6];
    u_int8_t bssId[6];
    u_int16_t seqNum;//Fragment Num(4) + Seq Num(12)
    //IEEE 80211 Mangment Field
}__attribute__((packed));

struct DataFrame{
//    struct RadioHeader rHeader;
    u_int16_t fc;//Frame Control
    u_int16_t duration;
    u_int8_t staAdd[6];
    u_int8_t bssId[6];
    u_int8_t srcAdd[6];
    u_int16_t seqNum;//Fragment Num(4) + Seq Num(12)
    //IEEE 80211 Mangment Field
}__attribute__((packed));

struct ApInfo{
    u_int8_t db;  
    u_int32_t bNum;//Beacon Number
    u_int32_t data;
    u_int8_t chnnel;
    u_int8_t mb;
    u_int8_t enc;
    u_int8_t ciper;
    u_int8_t auth;
    u_int8_t id_len;
    char * essid; 
    int essid_ckbit;
};
struct StaInfo{
    u_int8_t bssid[6];
    u_int8_t db;
    u_int8_t rate;
    u_int8_t lost;
    u_int32_t frameNum;
    u_int8_t id_len;
    char * essid;
    int bssid_ckbit;
    int essid_ckbit;
};
union ShareFrame{
    struct BeaconFrame bf;
    struct QosFrameStoA qfsa;
    struct QosFrameAtoS qfas;
    struct ProbFrame pf;
    struct DataFrame df;
};
#endif
