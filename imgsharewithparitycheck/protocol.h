#ifndef PROTOCOL_H
#define PROTOCOL_H


#include <stdint.h>
#define DATA_SIZE 1024

struct packet{
    uint32_t seq;
    uint16_t len;
    uint8_t parity;
    uint8_t data[DATA_SIZE];
};

typedef struct packet protopacket;


uint8_t compute_parity(uint8_t *data, int len);

inline uint8_t compute_parity(uint8_t *data, int len){
    uint8_t p = 0;
    for(int i = 0; i<len; i++){p ^= data[i];}
    return p;
}

#endif