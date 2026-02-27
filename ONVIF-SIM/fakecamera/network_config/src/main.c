#include <stdio.h>
#include "nic_config.h"

int main() {
    char nic_name[100];
    int choice;

    printf("Network Interface Configuration Tool (Netplan)\n");
    list_nics();

    printf("Enter the NIC name you want to configure (or 'exit' to quit): ");
    scanf("%s", nic_name);

    if (strcmp(nic_name, "exit") == 0) {
        printf("Exiting...\n");
        return 0;
    }

    show_nic_settings(nic_name);

    printf("Do you want to modify the settings? (1-Yes, 0-No): ");
    scanf("%d", &choice);

    if (choice == 1) {
        modify_nic_settings(nic_name);
    }

    return 0;
}
