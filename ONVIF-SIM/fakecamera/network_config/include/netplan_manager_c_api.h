#ifndef NETPLAN_MANAGER_C_API_H
#define NETPLAN_MANAGER_C_API_H
// #include "NetPlanManager.h"
#include "stdbool.h"
#if (defined(_WIN32) || defined(_WIN32_WCE))
#if defined(NETPLAN_MANAGER_EXPORTS)
#define NETPLAN_MANAGER_API __declspec(dllexport)
#else
#define NETPLAN_MANAGER_API __declspec(dllimport)
#endif
#elif defined(__GNUC__) && (__GNUC__ >= 4)
#define NETPLAN_MANAGER_API __attribute__((visibility("default")))
#else
#define NETPLAN_MANAGER_API
#endif

#ifdef __cplusplus
extern "C"
{
#endif

    // Forward declaration of NetPlanManager to avoid including the entire class header
    // typedef struct NetPlanManager NetPlanManager;

    // Create a NetPlanManager instance
    NETPLAN_MANAGER_API void *netplan_manager_create(const char *configFilePath);

    // Destroy the NetPlanManager instance
    NETPLAN_MANAGER_API void netplan_manager_destroy(void *manager);

    // List all NICs
    NETPLAN_MANAGER_API void netplan_manager_list_nics(void *manager);

    // Modify NIC settings
    NETPLAN_MANAGER_API void netplan_manager_modify_nic(void *manager, const char *nicName,
                                                        int useDHCP, const char *staticIP,
                                                        const char *gateway, const char *dns);

    NETPLAN_MANAGER_API int netplan_manager_read_config(void *manager);
    NETPLAN_MANAGER_API void netplan_manager_update_config(void *manager, const char *nicName, const bool dhcp4, const char *address, int prefixLength, const char *gateway, const char *dns);

    NETPLAN_MANAGER_API int netplan_manager_apply_changes(void *manager);
    NETPLAN_MANAGER_API void netplan_manager_get_all_dns_names(void *manager, char *dns);
    NETPLAN_MANAGER_API void netplan_manager_get_config(void *manager, const char *nicName, bool *dhcp4);
#ifdef __cplusplus
}
#endif

#endif // NETPLAN_MANAGER_C_API_H
