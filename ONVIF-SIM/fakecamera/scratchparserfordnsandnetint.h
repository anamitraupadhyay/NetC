// future modular template

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

typedef enum{
    ipv4, ipv6
}type;

typedef struct DNSManual{
    type addr;

    union {

    uint32_t ipv4;//ugh useless due to union but still
    uint64_t ipv6;

    } ipaddr;

}DNSManual;


typedef struct DNS{
    bool FromDHCP;
    int DNSManualflag;
    DNSManual *addrfmt;
}DNS;


void extract_fields_netdns(const char *buf){
    FILE *fp = fopen("config.xml", "r");
    fclose(fp);
}

void extract_fields_netint(const char *buf){
    FILE *fp = fopen("config.xml", "r");
    fclose(fp);
}