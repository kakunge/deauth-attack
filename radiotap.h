#pragma once
#pragma pack(1)

#include <cstdint>
#include <cstring>
#include <cstdlib>
#include <array>

using namespace std;

// ipTIME A2000UA-4dBi
struct Radiotap {
    uint8_t version = 0x00;
    uint8_t pad = 0x00;
    uint16_t len = 0x08;
    uint32_t present = 0x00000000;
};

struct Dot11Frame {
    uint8_t type;
    uint8_t flag;
};

struct BeaconFrame : Dot11Frame {
    uint16_t duration;
    uint8_t destAddr[6];
    uint8_t sourAddr[6];
    uint8_t BSSID[6];
    uint16_t seqControl;
    uint64_t timestamp;
    uint16_t beaconInterval;
    uint16_t capacityInfo;
};

struct Deauthentication : Dot11Frame {
    Deauthentication() : Dot11Frame{0xc0, 0x00} {}

    uint16_t duration = 0x0000;
    uint8_t destAddr[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    uint8_t sourAddr[6];
    uint8_t BSSID[6];
    uint16_t seqControl = 0x0000;
    uint16_t fixedParameter = 0x0007;
};

struct Authentication : Dot11Frame {
    Authentication() : Dot11Frame{0xb0, 0x00} {}

    uint16_t duration = 0x0000;
    uint8_t destAddr[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    uint8_t sourAddr[6];
    uint8_t BSSID[6];
    uint16_t seqControl = 0x0000;

    uint16_t fixedParameter = 0x0007;
};

struct Tag {
    uint8_t tagNumber;
    uint8_t tagLength;
};

struct SSIDParameter : Tag {
    array<uint8_t, 32> SSID = {};
};

struct SupportedRates : Tag {
    uint8_t supportedRates[8];
};

struct TrafficIndicationMap : Tag {
    uint8_t DTIMCount;
    uint8_t DTIMPeriod;
    uint8_t bitmapControl;
    uint8_t PVB;
};

struct HTCapabilities : Tag {
    uint16_t HTCapInfo;
    uint8_t A_MPDUParams;
    uint8_t MCSSet[16];
    uint16_t HTExtCaps;
    uint32_t TxBF;
    uint8_t ASEL; 
};

struct HTInformation : Tag {
    uint8_t PrimaryChan;
    uint8_t HTInfoSubset1;
    uint16_t HTInfoSubset2;
    uint16_t HTInfoSubset3;
    uint8_t MCSSet[16];
};

struct TestPacket {
    Radiotap radiotap;
    Deauthentication deauthentication;
};