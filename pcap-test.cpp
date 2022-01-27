#include "stdafx.h"
#include "ieee80211_header.h"
#include "myfunc.h"

struct ParsData pData;
std::map<std::array<u_int8_t,6>,struct ApInfo> ap_map;// ApMAC - Info mapping
std::map<std::array<u_int8_t,6>,struct StaInfo> sta_map;// ApMAC - staInfo mapping

void usage() {
	printf("syntax: pcap-test <interface>\n");
	printf("sample: pcap-test wlan0\n");
}

typedef struct {
	char* dev_;
} Param;

Param param  = {
	.dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
	if (argc != 2) {
		usage();
		return false;
	}
	param->dev_ = argv[1];
	return true;
}

int main(int argc, char* argv[]) {
	if (!parse(&param, argc, argv))
		return -1;

    char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
		return -1;
	}
    int i=0;
	while (true) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("\npcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}
        parsing(&pData,packet,header);

        if(pData.fc == BEACON || pData.fc == QOS || pData.fc == DATA){
            updateAP(pData, packet,pData.fc);
        }
        if(pData.fc == QOS || pData.fc == PROVRQ || pData.fc == DATA) {//if Qos,Request,Data
            updateSTA(pData, (ShareFrame *)&packet[pData.rH_len], pData.fc);
        }
        printAll();
		
	}

	pcap_close(pcap);
}

