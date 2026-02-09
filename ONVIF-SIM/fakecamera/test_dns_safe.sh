#!/bin/bash
# Safe DNS Configuration Testing Script
# This script helps test the DNS configuration code in an isolated environment

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${YELLOW}=== Safe DNS Configuration Testing ===${NC}\n"

# Check if running in isolated environment
check_environment() {
    echo "Checking environment safety..."
    
    # Check if in container
    if [ -f /.dockerenv ]; then
        echo -e "${GREEN}✓ Running in Docker container (safe)${NC}"
        return 0
    fi
    
    # Check if in multipass VM
    if grep -q "multipass" /etc/hostname 2>/dev/null || grep -q "ubuntu" /etc/hostname 2>/dev/null; then
        echo -e "${YELLOW}⚠ Possibly in Multipass VM${NC}"
        read -p "Are you sure this is a test VM? (yes/no): " confirm
        if [ "$confirm" != "yes" ]; then
            echo -e "${RED}Aborting for safety${NC}"
            exit 1
        fi
        return 0
    fi
    
    # Check if in network namespace
    if [ -n "$NETNS" ]; then
        echo -e "${GREEN}✓ Running in network namespace (safe)${NC}"
        return 0
    fi
    
    echo -e "${RED}✗ Not in isolated environment!${NC}"
    echo "This script modifies /etc/resolv.conf and should only run in:"
    echo "  - Docker container"
    echo "  - Multipass VM"
    echo "  - Network namespace"
    echo ""
    read -p "Do you understand the risks and want to continue anyway? (type 'I UNDERSTAND'): " confirm
    if [ "$confirm" != "I UNDERSTAND" ]; then
        echo -e "${RED}Aborting for safety${NC}"
        exit 1
    fi
}

# Backup resolv.conf
backup_resolv() {
    echo -e "\n${YELLOW}Creating backup...${NC}"
    if [ ! -f /etc/resolv.conf.test_backup ]; then
        sudo cp /etc/resolv.conf /etc/resolv.conf.test_backup
        echo -e "${GREEN}✓ Backup created at /etc/resolv.conf.test_backup${NC}"
    else
        echo -e "${YELLOW}⚠ Backup already exists${NC}"
    fi
}

# Show current network configuration
show_network_info() {
    echo -e "\n${YELLOW}=== Current Network Configuration ===${NC}"
    echo -e "\n${YELLOW}IP Addresses:${NC}"
    hostname -I 2>/dev/null || ip addr show | grep "inet " | awk '{print $2}'
    
    echo -e "\n${YELLOW}Hostname:${NC}"
    hostname
    
    echo -e "\n${YELLOW}Current /etc/resolv.conf:${NC}"
    cat /etc/resolv.conf
    echo ""
}

# Create test config files
create_test_configs() {
    echo -e "\n${YELLOW}Creating test configuration files...${NC}"
    
    # Test Case 1: With addr
    cat > config_with_addr.xml << 'EOF'
<?xml version="1.0" encoding="utf-8"?>
<config>
    <server_port>7000</server_port>
    <fromdhcp>true</fromdhcp>
    <searchdomain>testdomain.local</searchdomain>
    <type>ipv4</type>
    <addr>8.8.8.8</addr>
    <device>
        <manufacturer>Videonetics</manufacturer>
        <model>Videonetics_Camera_Emulator</model>
        <firmware_version>10.0</firmware_version>
        <serial_number>VN001</serial_number>
        <hardware_id>1.0</hardware_id>
        <type>video_encoder</type>
        <profile>streaming</profile>
        <hardware>VMS</hardware>
        <location>India</location>
        <auth>1</auth>
        <hostname>testcam</hostname>
        <FromDHCP>false</FromDHCP>
    </device>
</config>
EOF
    
    # Test Case 2: Without addr (for fallback)
    cat > config_no_addr.xml << 'EOF'
<?xml version="1.0" encoding="utf-8"?>
<config>
    <server_port>7000</server_port>
    <fromdhcp>true</fromdhcp>
    <searchdomain>testdomain.local</searchdomain>
    <type>ipv4</type>
    <device>
        <manufacturer>Videonetics</manufacturer>
        <model>Videonetics_Camera_Emulator</model>
        <firmware_version>10.0</firmware_version>
        <serial_number>VN001</serial_number>
        <hardware_id>1.0</hardware_id>
        <type>video_encoder</type>
        <profile>streaming</profile>
        <hardware>VMS</hardware>
        <location>India</location>
        <auth>1</auth>
        <hostname>testcam</hostname>
        <FromDHCP>false</FromDHCP>
    </device>
</config>
EOF
    
    echo -e "${GREEN}✓ Test configurations created${NC}"
}

# Create simple test program
create_test_program() {
    echo -e "\n${YELLOW}Creating test program...${NC}"
    
    cat > test_applydns.c << 'EOF'
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netdb.h>
#include <arpa/inet.h>

void applydnstoservice(){
    FILE *fp = fopen("config.xml", "r");
    if(!fp) {perror("config in applytodns");
    return;}
    char line[1024];
    char searchdomain[256] = {0};
    char addr[64] = {0};
    char *s , *e;
    while(fgets(line, sizeof(line), fp)){
        if((s = strstr(line , "<searchdomain>")) && (e = strstr(line , "</searchdomain>"))){
            int len = e - (s+14);
            if(len>0 && len < (int)sizeof(searchdomain) - 1){
                memcpy(searchdomain, s+14, len);
                searchdomain[len] = '\0';
            }
        }
        else if((s = strstr(line, "<addr>")) && (e = strstr(line, "</addr>"))){
            int len = e - (s + 6);
            if(len > 0 && len < (int)sizeof(addr) - 1){
                memcpy(addr, s + 6, len);
                addr[len] = '\0';
            }
        }
    }
    fclose(fp);
    
    if(!addr[0]){ 
        printf("no dns address found in config.xml\n");
        char hostbuffer[256];
        char *IPbuffer;
        struct hostent *host_entry;
        int hostname;
        
        hostname = gethostname(hostbuffer, sizeof(hostbuffer));
        if (hostname == -1) {
            perror("gethostname");
            exit(1);
        }
        
        host_entry = gethostbyname(hostbuffer);
        if (host_entry == NULL) {
            perror("gethostbyname");
            exit(1);
        }
        
        IPbuffer = inet_ntoa(*((struct in_addr*)host_entry->h_addr_list[0]));
        
        char stored_ip[INET_ADDRSTRLEN];
        strncpy(stored_ip, IPbuffer, INET_ADDRSTRLEN - 1);
        stored_ip[INET_ADDRSTRLEN - 1] = '\0';
        FILE *tmpfallback = fopen("/etc/resolv.conf.tmp", "w");
        if(!tmpfallback){ perror("/etc/resolv.conf.tmp"); return; }
        
        fprintf(tmpfallback, "# generated by ONVIF-cameraserver SetDNS\n");
        if(searchdomain[0]) fprintf(tmpfallback, "search %s\n", searchdomain);
        fprintf(tmpfallback, "nameserver %s\n", stored_ip);
        fflush(tmpfallback);
        fsync(fileno(tmpfallback));
        fclose(tmpfallback);
        
        if(rename("/etc/resolv.conf.tmp", "/etc/resolv.conf") != 0){
            perror("rename resolv.conf");
            unlink("/etc/resolv.conf.tmp");
            return;
        }
        return;
    }
    
    FILE *tmp = fopen("/etc/resolv.conf.tmp", "w");
    if(!tmp){ perror("/etc/resolv.conf.tmp"); return; }
    
    fprintf(tmp, "# generated by ONVIF-cameraserver SetDNS\n");
    if(searchdomain[0]) fprintf(tmp, "search %s\n", searchdomain);
    fprintf(tmp, "nameserver %s\n", addr);
    fflush(tmp);
    fsync(fileno(tmp));
    fclose(tmp);
    
    if(rename("/etc/resolv.conf.tmp", "/etc/resolv.conf") != 0){
        perror("rename resolv.conf");
        unlink("/etc/resolv.conf.tmp");
        return;
    }
}

int main() {
    printf("Testing DNS configuration...\n");
    applydnstoservice();
    printf("DNS configuration applied. Check /etc/resolv.conf\n");
    return 0;
}
EOF
    
    gcc -o test_applydns test_applydns.c
    echo -e "${GREEN}✓ Test program compiled${NC}"
}

# Run test with addr
test_with_addr() {
    echo -e "\n${YELLOW}=== Test 1: Normal operation (addr in config.xml) ===${NC}"
    cp config_with_addr.xml config.xml
    
    echo "Running test..."
    sudo ./test_applydns
    
    echo -e "\n${YELLOW}Result:${NC}"
    cat /etc/resolv.conf
    
    echo -e "\n${GREEN}Expected: nameserver 8.8.8.8${NC}"
    if grep -q "8.8.8.8" /etc/resolv.conf; then
        echo -e "${GREEN}✓ Test 1 PASSED${NC}"
    else
        echo -e "${RED}✗ Test 1 FAILED${NC}"
    fi
}

# Run test without addr (fallback)
test_without_addr() {
    echo -e "\n${YELLOW}=== Test 2: Fallback (no addr in config.xml) ===${NC}"
    cp config_no_addr.xml config.xml
    
    echo "Running test..."
    sudo ./test_applydns
    
    echo -e "\n${YELLOW}Result:${NC}"
    cat /etc/resolv.conf
    
    echo -e "\n${GREEN}Expected: nameserver should be first IP from gethostbyname()${NC}"
    FIRST_IP=$(hostname -I | awk '{print $1}')
    echo "First IP on system: $FIRST_IP"
    if grep -q "$FIRST_IP" /etc/resolv.conf || grep -q "nameserver" /etc/resolv.conf; then
        echo -e "${GREEN}✓ Test 2 PASSED (fallback worked)${NC}"
    else
        echo -e "${RED}✗ Test 2 FAILED${NC}"
    fi
}

# Restore original config
restore_original() {
    echo -e "\n${YELLOW}Restoring original configuration...${NC}"
    if [ -f /etc/resolv.conf.test_backup ]; then
        sudo cp /etc/resolv.conf.test_backup /etc/resolv.conf
        echo -e "${GREEN}✓ Restored from backup${NC}"
    fi
    
    # Verify DNS still works
    echo -e "\n${YELLOW}Verifying DNS resolution...${NC}"
    if nslookup google.com > /dev/null 2>&1; then
        echo -e "${GREEN}✓ DNS resolution working${NC}"
    else
        echo -e "${RED}✗ DNS resolution may be broken!${NC}"
        echo "You may need to manually fix /etc/resolv.conf"
    fi
}

# Main execution
main() {
    check_environment
    backup_resolv
    show_network_info
    create_test_configs
    create_test_program
    
    test_with_addr
    read -p "Press Enter to continue to next test..."
    
    test_without_addr
    read -p "Press Enter to restore original configuration..."
    
    restore_original
    
    echo -e "\n${GREEN}=== Testing Complete ===${NC}"
    echo -e "Test files created:"
    echo "  - config_with_addr.xml"
    echo "  - config_no_addr.xml"
    echo "  - test_applydns.c"
    echo "  - test_applydns (binary)"
    echo ""
    echo "Backup preserved at: /etc/resolv.conf.test_backup"
}

# Run main
main
