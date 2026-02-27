#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "nic_config.h"

#define MAX_CMD_LEN 256
#define NETPLAN_PATH "/etc/netplan/"

void list_nics() {
    printf("Listing available NIC cards...\n");
    system("ip link show | grep '^[0-9]:' | awk '{print $2}' | sed 's/://g'");
}

void show_nic_settings(char *nic_name) {
    char command[MAX_CMD_LEN];
    
    printf("\nShowing settings for NIC: %s\n", nic_name);
    snprintf(command, sizeof(command), "grep -A 5 %s %s*.yaml", nic_name, NETPLAN_PATH);
    system(command);
}

void modify_nic_settings(char *nic_name) {
    int config_choice;

    printf("Modify settings for %s:\n", nic_name);
    printf("1. Set DHCP\n");
    printf("2. Set Static IP\n");
    printf("Enter your choice (1 or 2): ");
    scanf("%d", &config_choice);

    if (config_choice == 1) {
        configure_dhcp(nic_name);
    } else if (config_choice == 2) {
        configure_static_ip(nic_name);
    } else {
        printf("Invalid choice.\n");
    }
}

void configure_dhcp(char *nic_name) {
    char command[MAX_CMD_LEN];
    printf("Setting DHCP for %s...\n", nic_name);

    snprintf(command, sizeof(command),
             "sudo sed -i '/%s:/!b;n;c\\      dhcp4: yes' %s*.yaml", nic_name, NETPLAN_PATH);

    system(command);
    system("sudo netplan apply");
    printf("DHCP configuration applied to %s.\n", nic_name);
}

void configure_static_ip(char *nic_name) {
    char ip[100], gateway[100], dns[100];
    char command[MAX_CMD_LEN];

    printf("Enter static IP address (e.g., 192.168.1.10/24): ");
    scanf("%s", ip);

    printf("Enter gateway (e.g., 192.168.1.1): ");
    scanf("%s", gateway);

    printf("Enter DNS server (e.g., 8.8.8.8): ");
    scanf("%s", dns);

    snprintf(command, sizeof(command),
             "sudo sed -i '/%s:/!b;n;c\\      dhcp4: no' %s*.yaml", nic_name, NETPLAN_PATH);
    system(command);

    snprintf(command, sizeof(command),
             "sudo sed -i '/%s:/!b;n;n;c\\      addresses: [%s]' %s*.yaml", nic_name, ip, NETPLAN_PATH);
    system(command);

    snprintf(command, sizeof(command),
             "sudo sed -i '/%s:/!b;n;n;n;c\\      gateway4: %s' %s*.yaml", nic_name, gateway, NETPLAN_PATH);
    system(command);

    snprintf(command, sizeof(command),
             "sudo sed -i '/%s:/!b;n;n;n;n;c\\      nameservers:\\n        addresses: [%s]' %s*.yaml",
             nic_name, dns, NETPLAN_PATH);
    system(command);

    system("sudo netplan apply");
    printf("Static IP configuration applied to %s.\n", nic_name);
}
