#include "netplan_manager_c_api.h"
#include "NetPlanManager.h"

// Create a void instance
void *netplan_manager_create(const char *configFilePath)
{
    return new NetPlanManager(std::string(configFilePath)); // Create and return a new instance
}

// Destroy the void instance
void netplan_manager_destroy(void *manager)
{

    delete static_cast<NetPlanManager *>(manager); // Delete the instance to free memory
}

// List all NICs
void netplan_manager_list_nics(void *manager)
{
    if (manager)
    {
        // Properly cast the void pointer and call the listNICs method
        static_cast<NetPlanManager *>(manager)->listNICs();
    }
}

// Modify NIC settings
void netplan_manager_modify_nic(void *manager, const char *nicName,
                                int useDHCP, const char *staticIP,
                                const char *gateway, const char *dns)
{
    if (manager)
    {
        // Properly cast the void pointer and call the modifyNICSettings method
        if (staticIP == nullptr)
        {
            staticIP = "";
        }
        if (gateway == nullptr)
        {
            gateway = "";
        }
        if (dns == nullptr)
        {
            dns = "";
        }
        static_cast<NetPlanManager *>(manager)->modifyNICSettings(nicName, useDHCP, staticIP, gateway, dns);
    }
}
int netplan_manager_read_config(void *manager)
{
    if (manager)
    {
        // Properly cast the void pointer and call the applyChanges method
        return static_cast<NetPlanManager *>(manager)->readNetplanConfig();
    }
    return -1;
}
void netplan_manager_update_config(void *manager, const char *nicName, bool dhcp4, const char *address, int prefixLength, const char *gateway, const char *dns)
{
    if (manager)
    {
        // Properly cast the void pointer and call the applyChanges method
        return static_cast<NetPlanManager *>(manager)->updateNetplanConfig(nicName, dhcp4, address, prefixLength, gateway, dns);
    }
    return;
}
// Apply changes to netplan
int netplan_manager_apply_changes(void *manager)
{
    if (manager)
    {
        // Properly cast the void pointer and call the applyChanges method
        return static_cast<NetPlanManager *>(manager)->applyChanges();
    }
    return -1;
}
void netplan_manager_get_all_dns_names(void *manager, char *dns)
{
    if (manager)
    {
        // Properly cast the void pointer and call the applyChanges method
        return static_cast<NetPlanManager *>(manager)->getAllDNSNames(dns);
    }
    return;
}
void netplan_manager_get_config(void *manager, const char *nicName, bool *dhcp4)
{
    if (manager)
    {
        // Properly cast the void pointer and call the applyChanges method
        return static_cast<NetPlanManager *>(manager)->getConfig(nicName, dhcp4);
    }
    return;
}