#ifndef NIC_CONFIG_H
#define NIC_CONFIG_H

void list_nics();
void show_nic_settings(char *nic_name);
void modify_nic_settings(char *nic_name);
void configure_dhcp(char *nic_name);
void configure_static_ip(char *nic_name);

#endif
