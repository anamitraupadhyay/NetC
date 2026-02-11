#ifndef INTERFACE_BINDING_H
#define INTERFACE_BINDING_H

#include <string.h>
#include <net/if.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <stdio.h>
#include <unistd.h>

// Internal state storage - using static inline functions to avoid multiple definition issues
static inline char* get_bind_interface_storage(void) {
    static char g_bind_interface[IFNAMSIZ] = {0};
    return g_bind_interface;
}

static inline char* get_bind_ip_storage(void) {
    static char g_bind_ip[INET_ADDRSTRLEN] = {0};
    return g_bind_ip;
}

/**
 * Set the network interface to bind to
 * @param interface_name: Interface name (e.g., "eth0") or IP address (e.g., "192.168.1.100")
 * @return 0 on success, -1 on error
 */
static inline int set_bind_interface(const char *interface_name) {
    if (!interface_name || strlen(interface_name) == 0) {
        return -1;
    }
    
    char *g_bind_interface = get_bind_interface_storage();
    char *g_bind_ip = get_bind_ip_storage();
    
    // Check if it's an IP address
    struct in_addr addr;
    if (inet_pton(AF_INET, interface_name, &addr) == 1) {
        // It's an IP address
        strncpy(g_bind_ip, interface_name, INET_ADDRSTRLEN - 1);
        g_bind_ip[INET_ADDRSTRLEN - 1] = '\0';
        g_bind_interface[0] = '\0';
        printf("[Interface Binding] Set to IP: %s\n", g_bind_ip);
        return 0;
    }
    
    // It's an interface name
    strncpy(g_bind_interface, interface_name, IFNAMSIZ - 1);
    g_bind_interface[IFNAMSIZ - 1] = '\0';
    g_bind_ip[0] = '\0';
    printf("[Interface Binding] Set to interface: %s\n", g_bind_interface);
    return 0;
}

/**
 * Get the IP address for the bound interface
 * @param ip_buf: Buffer to store the IP address
 * @param size: Size of the buffer
 * @return 0 on success, -1 on error
 */
static inline int get_bound_ip_address(char *ip_buf, size_t size) {
    char *g_bind_interface = get_bind_interface_storage();
    char *g_bind_ip = get_bind_ip_storage();
    
    if (g_bind_ip[0] != '\0') {
        // IP was directly specified
        strncpy(ip_buf, g_bind_ip, size - 1);
        ip_buf[size - 1] = '\0';
        return 0;
    }
    
    if (g_bind_interface[0] == '\0') {
        // No binding configured, return error
        return -1;
    }
    
    // Find the IP address for the interface
    struct ifaddrs *ifaddr, *ifa;
    if (getifaddrs(&ifaddr) == -1) {
        perror("getifaddrs");
        return -1;
    }
    
    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL) continue;
        
        if (strcmp(ifa->ifa_name, g_bind_interface) == 0 && 
            ifa->ifa_addr->sa_family == AF_INET) {
            struct sockaddr_in *saddr = (struct sockaddr_in *)ifa->ifa_addr;
            inet_ntop(AF_INET, &saddr->sin_addr, ip_buf, size);
            freeifaddrs(ifaddr);
            return 0;
        }
    }
    
    freeifaddrs(ifaddr);
    fprintf(stderr, "[Interface Binding] Could not find IP for interface: %s\n", g_bind_interface);
    return -1;
}

/**
 * Apply interface binding to a socket
 * This should be called after socket creation but before bind()
 * @param sockfd: Socket file descriptor
 * @return 0 on success, -1 on error
 */
static inline int apply_interface_binding(int sockfd) {
    char *g_bind_interface = get_bind_interface_storage();
    char *g_bind_ip = get_bind_ip_storage();
    
    if (g_bind_interface[0] == '\0' && g_bind_ip[0] == '\0') {
        // No binding configured, skip
        return 0;
    }
    
    if (g_bind_interface[0] != '\0') {
        // Bind to specific interface using SO_BINDTODEVICE
        struct ifreq ifr;
        memset(&ifr, 0, sizeof(ifr));
        strncpy(ifr.ifr_name, g_bind_interface, IFNAMSIZ - 1);
        
        if (setsockopt(sockfd, SOL_SOCKET, SO_BINDTODEVICE, &ifr, sizeof(ifr)) < 0) {
            perror("[Interface Binding] SO_BINDTODEVICE failed");
            return -1;
        }
        printf("[Interface Binding] Socket bound to interface: %s\n", g_bind_interface);
    }
    
    return 0;
}

/**
 * Get the bind address for socket binding
 * Instead of INADDR_ANY, returns the specific IP address if configured
 * @param addr: Output parameter for the address
 * @return 0 on success (addr will be INADDR_ANY or specific IP), -1 on error
 */
static inline int get_bind_address(struct in_addr *addr) {
    char *g_bind_interface = get_bind_interface_storage();
    char *g_bind_ip = get_bind_ip_storage();
    
    if (g_bind_ip[0] != '\0') {
        // Use specific IP
        if (inet_pton(AF_INET, g_bind_ip, addr) != 1) {
            return -1;
        }
        return 0;
    }
    
    if (g_bind_interface[0] != '\0') {
        // Get IP from interface name
        char ip_buf[INET_ADDRSTRLEN];
        if (get_bound_ip_address(ip_buf, sizeof(ip_buf)) == 0) {
            if (inet_pton(AF_INET, ip_buf, addr) == 1) {
                return 0;
            }
        }
        return -1;
    }
    
    // No binding configured, use INADDR_ANY
    addr->s_addr = INADDR_ANY;
    return 0;
}

/**
 * Get the multicast interface address
 * For IP_ADD_MEMBERSHIP, instead of INADDR_ANY
 * @param addr: Output parameter for the interface address
 * @return 0 on success, -1 on error
 */
static inline int get_multicast_interface(struct in_addr *addr) {
    char *g_bind_interface = get_bind_interface_storage();
    char *g_bind_ip = get_bind_ip_storage();
    
    if (g_bind_ip[0] != '\0') {
        // Use specific IP
        if (inet_pton(AF_INET, g_bind_ip, addr) != 1) {
            return -1;
        }
        printf("[Interface Binding] Multicast interface set to: %s\n", g_bind_ip);
        return 0;
    }
    
    if (g_bind_interface[0] != '\0') {
        // Get IP from interface name
        char ip_buf[INET_ADDRSTRLEN];
        if (get_bound_ip_address(ip_buf, sizeof(ip_buf)) == 0) {
            if (inet_pton(AF_INET, ip_buf, addr) == 1) {
                printf("[Interface Binding] Multicast interface set to: %s\n", ip_buf);
                return 0;
            }
        }
        return -1;
    }
    
    // No binding configured, use INADDR_ANY
    addr->s_addr = INADDR_ANY;
    return 0;
}

/**
 * Check if interface binding is configured
 * @return 1 if configured, 0 otherwise
 */
static inline int is_interface_binding_enabled(void) {
    char *g_bind_interface = get_bind_interface_storage();
    char *g_bind_ip = get_bind_ip_storage();
    return (g_bind_interface[0] != '\0' || g_bind_ip[0] != '\0');
}

#endif // INTERFACE_BINDING_H
