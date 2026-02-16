#ifndef SIMPLEPARSER_H
#define SIMPLEPARSER_H

#include <arpa/inet.h>
#include <cstdint>
#include <ifaddrs.h>
#include <stdint.h>
#include <uchar.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#include "config.h"

static inline uint8_t get_the_tag(
    const char *line, // the buffer line to read from
    const char *tag, // xml tag <%s> and </%s> and %s is server_id
    char *out, // the output buffer as inited from the calling function
    size_t out_size // the output size of buf
){
    char open[64], close[64];
    snprintf(open, sizeof(open), "<%s>", tag);
    snprintf(close, sizeof(close), "</%s>", tag);
    // set from tag both opened and closed, no need for closed tag input duh!
    const char *start = strstr(line, open);
    if (!start) return 0;
    
    start += strlen(open);
    
    const char *end = strstr(start, close);
    if (!end) return 0;
    
    size_t len = end - start;
    if (len >= out_size) len = out_size - 1;
    
    memcpy(out, start, len);
    out[len] = '\0';
    
    return 1;
}

static inline int load_config(const char *filename, config *cfg)
{
    FILE *fp = fopen(filename, "r");
    if (!fp) return 0;

    char line[256];
    char buf[128];

    while (fgets(line, sizeof(line), fp)) {

        if (get_the_tag(line, "server_port", buf, sizeof(buf)))
            cfg->server_port = (uint16_t)atoi(buf);

        else if (get_the_tag(line, "manufacturer", cfg->manufacturer,
                                   sizeof(cfg->manufacturer)));
            

        else if (get_the_tag(line, "model", 
                                    cfg->model,
                                    sizeof(cfg->model)));
            

        else if (get_the_tag(line, "firmware_version", buf, sizeof(buf)))
            cfg->firmware_version = (float)atof(buf);

        else if (get_the_tag(line, "serial_number",
                                   cfg->serial_number,
                                   sizeof(cfg->serial_number)));
        //here extraction instead of the above 
        // 2 ways it can be total fix here or below where minimal fix affecting only when needed though consistency is needed 
        // 
        
        else if(get_the_tag(line, "hardware", 
                                   cfg->hardware, 
                                   sizeof(cfg->hardware)));
        
        else if(get_the_tag(line, "location", 
                                   cfg->location, 
                                   sizeof(cfg->location)));
        
        else if(get_the_tag(line, "profile", 
                                   cfg->profile, 
                                   sizeof(cfg->profile)));
        
        else if(get_the_tag(line, "type", 
                                   cfg->type, 
                                   sizeof(cfg->type)));
            

        else if (get_the_tag(line, "hardware_id", buf,sizeof(buf)))
            cfg->hardware_id = (float)atoi(buf);
            
        else if(get_the_tag(line, "hostname", cfg->hostname, sizeof(cfg->hostname)));
            
        else if(get_the_tag(line, "FromDHCP", cfg->fromdhcp, sizeof(cfg->fromdhcp))){}

        else if (get_the_tag(line, "auth", buf, sizeof(buf)))
            cfg->auth_enabled = atoi(buf);

        else if(get_the_tag(line, "scopes", cfg->scopes, sizeof(cfg->scopes)));
    }

    fclose(fp);
    return 1;
}

static uint8_t getcloudconfig(const char *filename){
    //
    FILE *file = fopen(filename, "r");
    char line[256];
    uint8_t id[16]; // 16-byte ID
    while (fgets(line, sizeof(line), file))
    {
        if (strstr(line, "VTPL_VSAAS_UNIQUE_ID=") != NULL)
        {
            //extract the value and return
            fclose(file);
            return *id;
        }
    }

    fclose(file);
    return 1;//return some default fallback
}

static int load_config_for_getdevice_info(const char *filename, config *cfg){
    FILE *fp = fopen(filename, "r");
    
    const char *filename1 = "./vtpl_cnf/vsaas_cloud_config.cnf";
    getcloudconfig(filename1);
    // only for th
}


#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <ifaddrs.h>
#include <netdb.h>

// Helper to get MAC Address and MTU for a specific interface name (e.g., "eth0")
// Returns 0 on success, -1 on error
int get_hw_info(const char *ifname, char *mac_out, int *mtu_out) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return -1;

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);

    // 1. Get MAC Address
    if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) {
        close(fd);
        return -1;
    }
    unsigned char *mac = (unsigned char *)ifr.ifr_hwaddr.sa_data;
    sprintf(mac_out, "%02X:%02X:%02X:%02X:%02X:%02X",
            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

    // 2. Get MTU
    if (ioctl(fd, SIOCGIFMTU, &ifr) < 0) {
        close(fd);
        return -1;
    }
    *mtu_out = ifr.ifr_mtu;

    close(fd);
    return 0;
}

// Helper to calculate CIDR prefix from netmask (e.g., 255.255.255.0 -> 24)
int netmask_to_prefix(struct sockaddr *netmask) {
    if (!netmask) return 0;
    struct sockaddr_in *nm = (struct sockaddr_in *)netmask;
    uint32_t mask = ntohl(nm->sin_addr.s_addr);
    int prefix = 0;
    while (mask > 0) {
        if (mask & 1) prefix++; // This counts bits from the wrong end if not contiguous, 
                                // but standard masks are contiguous. 
                                // Better algorithm:
        mask = mask << 1;
    }
    mask = ntohl(nm->sin_addr.s_addr);
    prefix = 0;
    for (int i = 0; i < 32; i++) {
        if ((mask >> i) & 1) prefix++;
    }
    return prefix;
}


int scan_interfaces(Interfacedata *data, int maxitems/*macro for now*/){
    struct ifaddrs *ifaddr, *ifa;
    if(getifaddrs(&ifaddr) == -1 )return 0;
    int count = 0;
    for (ifa = ifaddr; ifa != NULL && count < maxitems; ifa = ifa->ifa_next){
        if(ifa->ifa_addr == NULL) continue;
        if (ifa->ifa_addr->sa_family == AF_INET && strcmp(ifa->ifa_name, "lo") != 0
            && strncmp(ifa->ifa_name, "docker", 6) != 0
            && strncmp(ifa->ifa_name, "br-", 3) != 0
            && strncmp(ifa->ifa_name, "veth", 4) != 0) {
                    strncpy(data[count].name, ifa->ifa_name, 31);
                    
                    struct sockaddr_in *paddr = (struct sockaddr_in *)ifa->ifa_addr;
                    
                    inet_ntop(AF_INET, &paddr->sin_addr, data[count].ip, 64);
                    
                    get_hw_info(data[count].name, data[count].mac, &data[count].mtu);
                    
                    data[count].prefix_len = netmask_to_prefix(ifa->ifa_netmask);
                    
                    count++;
                }
            }
            
            freeifaddrs(ifaddr);
            return count;
}

#endif /* SIMPLEPARSER_H */