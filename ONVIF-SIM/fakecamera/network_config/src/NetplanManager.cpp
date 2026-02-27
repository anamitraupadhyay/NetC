#include "NetPlanManager.h"
#include <iostream>
#include <fstream>
#include <yaml-cpp/yaml.h> // You'll need yaml-cpp to parse the YAML
#include "sys_log.h"
#include <Poco/Process.h>
#include <Poco/Pipe.h>
#include <Poco/PipeStream.h>
#include <Poco/Exception.h>

NetPlanManager::NetPlanManager(const std::string &configFilePath) : configFilePath_(configFilePath)
{
    // #if __WINDOWS_OS__
    //     log_init(".\\logs\\vsaas-edge-box-netplan-manager.txt");
    // #else
    //     log_init("./logs/vsaas-edge-box-netplan-manager.txt");
    // #endif
    // Check if the Open vSwitch database socket is available
}
NetPlanManager::~NetPlanManager()
{
    // log_close();
}
int NetPlanManager::readNetplanConfig()
{
    int ret = 0;
    try
    {
        YAML::Node config = YAML::LoadFile(configFilePath_);
        auto ethernets = config["network"]["ethernets"];

        for (auto it = ethernets.begin(); it != ethernets.end(); ++it)
        {
            std::string nicName = it->first.as<std::string>();
            std::map<std::string, std::string> settings;

            if (ethernets[nicName]["dhcp4"])
            {
                settings["dhcp4"] = ethernets[nicName]["dhcp4"].as<std::string>();
            }
            else
            {
                settings["dhcp4"] = "false";
            }

            if (ethernets[nicName]["addresses"])
            {
                settings["address"] = ethernets[nicName]["addresses"][0].as<std::string>();

                if (ethernets[nicName]["routes"])
                {
                    auto routes = ethernets[nicName]["routes"];
                    std::string gatewaysList;
                    for (size_t i = 0; i < routes.size(); ++i)
                    {
                        if (routes[i]["gateway"])
                        {
                            if (i > 0)
                                gatewaysList += ",";
                            gatewaysList += routes[i]["via"].as<std::string>();
                        }
                    }
                    settings["gateway"] = gatewaysList;
                }
                else
                {
                    settings["gateway"] = "172.16.0.1";
                }
                if (ethernets[nicName]["nameservers"]["addresses"])
                {
                    auto dnsNodes = ethernets[nicName]["nameservers"]["addresses"];
                    std::string dnsList;
                    for (size_t i = 0; i < dnsNodes.size(); ++i)
                    {
                        if (i > 0)
                            dnsList += ",";
                        dnsList += dnsNodes[i].as<std::string>();
                    }
                    settings["dns"] = dnsList;
                }
                else
                {
                    settings["dns"] = "N/A"; // Placeholder if no DNS is specified
                }
                //settings["dns"] = ethernets[nicName]["nameservers"]["addresses"][0].as<std::string>();
            }

            nics[nicName] = settings;
        }
    }
    catch (const YAML::Exception &e)
    {
        log_print(HT_LOG_ERR, "%s, Error parsing netplan config: %s!!!\r\n", __FUNCTION__, e.what());
        ret = -1;
    }
    return ret;
}
void NetPlanManager::listNICs()
{
    std::cout << "NIC Cards and their current settings:" << std::endl;
    for (const auto &nic : nics)
    {
        std::cout << "NIC: " << nic.first << std::endl;
        std::cout << "  DHCP: " << nic.second.at("dhcp4") << std::endl;

        if (nic.second.at("dhcp4") == "false")
        {
            std::cout << "  IP Address: " << nic.second.at("address") << std::endl;
            std::cout << "  Gateway: " << nic.second.at("gateway") << std::endl;
            std::cout << "  DNS: " << nic.second.at("dns") << std::endl;
        }
    }
}
void NetPlanManager::modifyNICSettings(const std::string &nicName, bool useDHCP,
                                       const std::string &staticIP, const std::string &gateway,
                                       const std::string &dns)
{

    if (nics.empty())
    {
        printf("%s, Error: NIC map is empty.\r\n", __FUNCTION__);
        return; // Exit if NIC map is empty
    }

    auto it = nics.find(nicName);
    if (it == nics.end())
    {
        printf("%s, Error NIC: %s not found!!!\r\n", __FUNCTION__, nicName.c_str());
        return; // Exit if NIC is not found
    }

    if (useDHCP)
    {
        nics[nicName]["dhcp4"] = "true";
    }
    else
    {
        nics[nicName]["dhcp4"] = "false";
        if (!staticIP.empty())
        {
            nics[nicName]["address"] = staticIP;
        }

        if (!gateway.empty())
        {
            nics[nicName]["gateway"] = gateway;
        }

        if (!dns.empty())
        {
            nics[nicName]["dns"] = dns;
        }
    }
}
void NetPlanManager::updateNetplanConfig(const char *nicName, bool dhcp4, const char *address, int prefixLength, const char *gateway, const char *dns)
{
    try
    {
        // Create a map to store NIC settings
        std::map<std::string, std::string> settings;

        // Set DHCP
        if (dhcp4)
        {
            settings["dhcp4"] = "true";
        }
        else
        {
            settings["dhcp4"] = "false";

            // Store IP address, gateway, and DNS when DHCP is disabled
            settings["address"] = std::string(address) + "/" + std::to_string(prefixLength);
            settings["gateway"] = std::string(gateway);
            settings["dns"] = std::string(dns);
        }

        // Update the nics map with the new settings
        nics[nicName] = settings;
        log_print(HT_LOG_INFO, "%s, Netplan configuration updated in memory for NIC:\r\n", __FUNCTION__, nicName);
    }
    catch (const std::exception &e)
    {
        log_print(HT_LOG_ERR, "%s, Error updating netplan config in memory: %s\r\n", __FUNCTION__, e.what());
    }
}
int NetPlanManager::writeNetplanConfig()
{
    YAML::Node config;
    YAML::Node ethernets;

    for (const auto &nic : nics)
    {
        YAML::Node node;

        // DHCP4 setting
        bool isDhcp = (nic.second.at("dhcp4") == "true");
        node["dhcp4"] = isDhcp;

        if (!isDhcp)
        {
            // Static IP address
            if (nic.second.count("address"))
            {
                node["addresses"].push_back(nic.second.at("address"));
            }

            // Handle gateway(s) as routes
            if (nic.second.count("gateway") && !nic.second.at("gateway").empty())
            {
                std::stringstream ss(nic.second.at("gateway"));
                std::string token;
                while (std::getline(ss, token, ','))
                {
                    // Trim whitespace
                    token.erase(token.begin(), std::find_if(token.begin(), token.end(), [](unsigned char ch)
                                                            { return !std::isspace(ch); }));
                    token.erase(std::find_if(token.rbegin(), token.rend(), [](unsigned char ch)
                                             { return !std::isspace(ch); })
                                    .base(),
                                token.end());

                    if (!token.empty())
                    {
                        
                        YAML::Node route;
                        route["to"] = "0.0.0.0/0"; // Default route
                        route["via"] = token;
                        node["routes"].push_back(route);
                    }
                }
            }

            // Handle DNS addresses
            YAML::Node dnsNode;
            if (nic.second.count("dns") && !nic.second.at("dns").empty())
            {
                std::stringstream ss(nic.second.at("dns"));
                std::string token;
                while (std::getline(ss, token, ','))
                {
                    // Trim whitespace
                    token.erase(token.begin(), std::find_if(token.begin(), token.end(), [](unsigned char ch)
                                                            { return !std::isspace(ch); }));
                    token.erase(std::find_if(token.rbegin(), token.rend(), [](unsigned char ch)
                                             { return !std::isspace(ch); })
                                    .base(),
                                token.end());

                    if (!token.empty())
                    {
                        dnsNode["addresses"].push_back(token);
                    }
                }

                if (dnsNode["addresses"] && dnsNode["addresses"].size() > 0)
                {
                    node["nameservers"] = dnsNode;
                }
            }
        }

        // Add to ethernets section
        ethernets[nic.first] = node;
    }

    config["network"]["ethernets"] = ethernets;
    config["network"]["version"] = 2;

    // Emit YAML string
    YAML::Emitter out;
    out << config;

    std::string yamlContent = out.c_str();

    // Log emitted configuration
    log_print(HT_LOG_INFO, "%s, Generated Netplan Configuration: %s\r\n", __FUNCTION__, yamlContent.c_str());
    log_print(HT_LOG_INFO, "%s, Writing to config file path: %s\r\n", __FUNCTION__, configFilePath_);

    // Write to file
    std::ofstream fout(configFilePath_);
    if (!fout.is_open())
    {
        log_print(HT_LOG_ERR, "%s, Failed to open config file for writing: %s\r\n", __FUNCTION__, configFilePath_);
        return -1;
    }

    fout << yamlContent << std::flush;
    fout.close();

    return 0;
}

std::string NetPlanManager::getDNSName(const std::string &nicName)
{
    if (nics.find(nicName) == nics.end())
    {
        log_print(HT_LOG_ERR, "%s, NIC %s not found!!!\r\n", __FUNCTION__, nicName);
        return "";
    }

    // Check if the NIC uses DHCP or has static settings
    if (nics.at(nicName).at("dhcp4") == "false")
    {
        return nics.at(nicName).at("dns");
    }

    return "DHCP mode does not have a static DNS entry";
}
void NetPlanManager::getAllDNSNames(char *dns)
{

    if (!dns)
    {
        return;
    }

    if (nics.begin()->second.find("dns") != nics.begin()->second.end() &&
        !nics.begin()->second.at("dns").empty())
    {
        *((int *)dns) = 1;
    }
    else
    {
        *((int *)dns) = 0;
    }
    NIC_DNS *dnsStructArray = (NIC_DNS *)(dns + sizeof(int));

    int index = 0;

    for (const auto &nic : nics)
    {

        std::string dns = getDNSName(nic.first);
        strncpy(dnsStructArray[index].nicName, nic.first.c_str(), sizeof(dnsStructArray[index].nicName) - 1);
        dnsStructArray[index].nicName[sizeof(dnsStructArray[index].nicName) - 1] = '\0';

        strncpy(dnsStructArray[index].dns, dns.c_str(), sizeof(dnsStructArray[index].dns) - 1);
        dnsStructArray[index].dns[sizeof(dnsStructArray[index].dns) - 1] = '\0';

        index++;
    }

    return;
}
void NetPlanManager::getConfig(const char *nicName, bool *dhcp4)

{

    if (!nics.empty() && nics.find(nicName) == nics.end())
    {
        log_print(HT_LOG_ERR, "%s, Error NIC: %s not found!!!\r\n", __FUNCTION__, nicName);
        nicName = nullptr;
        return;
    }

    if (dhcp4)
    {
        *dhcp4 = (nics[nicName]["dhcp4"] == "true");
    }

    log_print(HT_LOG_INFO, "NIC: %s, DHCP: %s\r\n",
              nicName, *dhcp4 ? "enabled" : "disabled");
    return;
}
int NetPlanManager::applyChanges()
{
    int result = writeNetplanConfig();
    if (result != 0)
        return result;
    int val = access("/var/run/openvswitch/db.sock", F_OK);
    log_print(HT_LOG_INFO, "%s, Open vSwitch val = %d...\r\n", __FUNCTION__, val);

    // Socket does not exist, start Open vSwitch
    log_print(HT_LOG_INFO, "%s, Open vSwitch socket not found, starting Open vSwitch...\r\n", __FUNCTION__);

    try
    {
        // Prepare to run the command using Poco::Process
        Poco::Pipe outPipe;
        Poco::Pipe errPipe;
        Poco::Process::Args args;
        args.push_back("start");

        // Launch the OVS control script
        Poco::ProcessHandle ph = Poco::Process::launch("/usr/share/openvswitch/scripts/ovs-ctl", args, nullptr, &outPipe, &errPipe);

        // Capture the output from the command
        Poco::PipeInputStream istr(outPipe);
        Poco::PipeInputStream errstr(errPipe);
        std::string output;
        std::string errorOutput;
        std::string line;

        // Read the output from the standard output stream
        while (std::getline(istr, line))
        {
            output += line + "\n";
        }

        // Read the output from the error stream
        while (std::getline(errstr, line))
        {
            errorOutput += line + "\n";
        }

        // Wait for the process to complete and get the exit status
        int status = ph.wait();

        // Log the output
        if (status == 0)
        {
            log_print(HT_LOG_INFO, "%s, Open vSwitch started successfully: %s\r\n", __FUNCTION__, output.c_str());
        }
        else
        {
            log_print(HT_LOG_ERR, "%s, Failed to start Open vSwitch: %s\r\n", __FUNCTION__, errorOutput.c_str());
        }
    }
    catch (const Poco::Exception &e)
    {
        log_print(HT_LOG_ERR, "%s, Exception while starting Open vSwitch: %s\r\n", __FUNCTION__, e.displayText().c_str());
    }

    sleep(5); // Adjust as needed

    try
    {
        // Prepare to run the command using Poco::Process
        Poco::Pipe outPipe;
        Poco::Process::Args args;
        args.push_back("apply");

        // Run the command
        Poco::ProcessHandle ph = Poco::Process::launch("netplan", args, nullptr, &outPipe, &outPipe);

        // Capture the output from the command
        Poco::PipeInputStream istr(outPipe);
        std::string output;
        std::string line;
        while (std::getline(istr, line))
        {
            output += line + "\n";
        }

        // Wait for the process to complete and get the exit status
        int status = ph.wait();

        // Log the output
        if (status == 0)
        {
            if (output.empty())
            {
                log_print(HT_LOG_INFO, "%s, Netplan apply successful: No output received.\r\n", __FUNCTION__);
            }
            else
            {
                log_print(HT_LOG_INFO, "%s, Netplan apply successful: %s\r\n", __FUNCTION__, output.c_str());
            }
        }
        else
        {
            log_print(HT_LOG_ERR, "%s, Netplan apply failed: %s\r\n", __FUNCTION__, output.c_str());
        }

        return (status == 0) ? 0 : -1;
    }
    catch (const Poco::Exception &e)
    {
        log_print(HT_LOG_ERR, "%s, Failed to run netplan apply command: %s\r\n", __FUNCTION__, e.displayText().c_str());
        return -1;
    }
}