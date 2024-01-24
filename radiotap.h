#pragma once
#pragma pack(1)

#include <cstdint>
#include <cstring>

using namespace std;

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

struct Deauthentication : Dot11Frame {
    Deauthentication() : Dot11Frame{0xc0, 0x00} {}

    uint16_t duration = 0x0000;
    uint8_t destAddr[6];
    uint8_t sourAddr[6];
    uint8_t BSSID[6];
    uint16_t seqControl = 0x0000;
    uint16_t fixedParameter = 0x0007;
};

struct Authentication : Dot11Frame {
    Authentication() : Dot11Frame{0xb0, 0x00} {}

    uint16_t duration = 0x0000;
    uint8_t destAddr[6];
    uint8_t sourAddr[6];
    uint8_t BSSID[6];
    uint16_t seqControl = 0x0000;
    uint16_t fixedParameter[3] = {0x0000, 0x0001, 0x0000};
};

template <typename FrameType>
struct TestPacket {
    Radiotap radiotap;
    FrameType frame;
};