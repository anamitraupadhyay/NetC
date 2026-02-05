#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

typedef enum{
    ipv4, ipv6
}addrformat;

struct DNSManual{
    addrformat addr;
    uint32_t ipv4;
    uint64_t ipv6;
};
typedef struct {
    bool FromDHCP;
    int DNSManualflag;
    struct DNSManual *addrfmt;
}DNS;


void extract_fields_netdns(const char *buf){
    FILE *fp = fopen("config.xml", "r");
}

void extract_fields_netint(const char *buf){
    FILE *fp = fopen("config.xml", "r");
}