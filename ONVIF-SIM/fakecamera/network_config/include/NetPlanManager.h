#ifndef NETPLAN_MANAGER_H
#define NETPLAN_MANAGER_H

#include <string>
#include <vector>
#include <map>
#include <stdio.h>
#include <string.h>
struct NIC_DNS
{
    char nicName[100];
    char dns[32];
};
class NetPlanManager
{
public:
    // Constructor
    NetPlanManager(const std::string &configFilePath);
    ~NetPlanManager();


    // Identify all NICs and their settings
    void listNICs();

    void updateNetplanConfig(const char *nicName, const bool dhcp4, const char *address, int prefixLength, const char *gateway, const char *dns);

    int readNetplanConfig();
    void modifyNICSettings(const std::string &nicName, bool useDHCP,
                           const std::string &staticIP = "", const std::string &gateway = "",
                           const std::string &dns = "");

    int applyChanges();
    void getAllDNSNames(char *dns);
    void getConfig(const char *nicName, bool *dhcp4);

private:
    std::string configFilePath_;
    std::map<std::string, std::map<std::string, std::string>> nics; // NICs with their config

    // Helper to read netplan YAML

    // Helper to write modified netplan config
    int writeNetplanConfig();
    std::string getDNSName(const std::string &nicName);
};

#endif // NETPLAN_MANAGER_H
