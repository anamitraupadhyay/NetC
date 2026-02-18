#include "netplan_manager_c_api.h" // Include the C API header
#include <iostream>

int main()
{
    // Create an instance of NetPlanManager using the C API
    const char *configFilePath = "/etc/netplan/00-installer-config.yaml";
    void *manager = netplan_manager_create(configFilePath);
    if (!manager)
    {
        std::cerr << "Failed to create NetPlanManager instance." << std::endl;
        return 1;
    }
    netplan_manager_read_config(manager);

    // List all network interface cards (NICs) using C API
    netplan_manager_list_nics(manager);

    // Prompt the user to modify a NIC
    std::cout << "Do you want to modify a NIC? (y/n): ";
    char choice;
    std::cin >> choice;

    if (choice == 'y' || choice == 'Y')
    {
        char nicName[256];
        std::cout << "Enter NIC name: ";
        std::cin >> nicName;

        // Ask if the user wants to use DHCP
        std::cout << "Use DHCP? (y/n): ";
        std::cin >> choice;
        int useDHCP = (choice == 'y' || choice == 'Y') ? 1 : 0;

        // If not using DHCP, gather static IP information
        if (!useDHCP)
        {
            char staticIP[16], gateway[16], dns[16];
            std::cout << "Enter static IP: ";
            std::cin >> staticIP;
            std::cout << "Enter gateway: ";
            std::cin >> gateway;
            std::cout << "Enter DNS: ";
            std::cin >> dns;

            // Modify NIC settings using C API
            netplan_manager_modify_nic(manager, nicName, useDHCP, staticIP, gateway, dns);
        }
        else
        {
            // Modify NIC settings to use DHCP using C API
            netplan_manager_modify_nic(manager, nicName, useDHCP, nullptr, nullptr, nullptr);
        }

        // Apply changes to the netplan configuration using C API
        netplan_manager_apply_changes(manager);
        std::cout << "Changes applied successfully." << std::endl;
    }
    else
    {
        std::cout << "No modifications made." << std::endl;
    }

    // Destroy the NetPlanManager instance using the C API
    netplan_manager_destroy(manager);
    return 0;
}
