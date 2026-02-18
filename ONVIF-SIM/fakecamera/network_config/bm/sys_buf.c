/***************************************************************************************
 *
 *  IMPORTANT: READ BEFORE DOWNLOADING, COPYING, INSTALLING OR USING.
 *
 *  By downloading, copying, installing or using the software you agree to this license.
 *  If you do not agree to this license, do not download, install,
 *  copy or use the software.
 *
 *  Copyright (C) 2014-2021, Happytimesoft Corporation, all rights reserved.
 *
 *  Redistribution and use in binary forms, with or without modification, are permitted.
 *
 *  Unless required by applicable law or agreed to in writing, software distributed
 *  under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
 *  CONDITIONS OF ANY KIND, either express or implied. See the License for the specific
 *  language governing permissions and limitations under the License.
 *
****************************************************************************************/

#include "sys_inc.h"
#include "sys_buf.h"

/***************************************************************************************/
PPSN_CTX *net_buf_fl = NULL;

PPSN_CTX *hdrv_buf_fl = NULL;

/***************************************************************************************/
HT_API BOOL net_buf_init(int num, int size)
{
	net_buf_fl = pps_ctx_fl_init(num, size, TRUE);
	if (net_buf_fl == NULL)
	{
		return FALSE;
	}

	log_print(HT_LOG_INFO, "%s, num = %lu\r\n", __FUNCTION__, net_buf_fl->node_num);

	return TRUE;
}

HT_API char *net_buf_get_idle()
{
	return (char *)pps_fl_pop(net_buf_fl);
}

HT_API void net_buf_free(char *rbuf)
{
	if (rbuf == NULL)
	{
		return;
	}

	if (pps_safe_node(net_buf_fl, rbuf))
	{
		pps_fl_push_tail(net_buf_fl, rbuf);
	}
	else
	{
		free(rbuf);
	}
}

HT_API uint32 net_buf_get_size()
{
	if (net_buf_fl == NULL)
	{
		return 0;
	}

	return (net_buf_fl->unit_size - sizeof(PPSN));
}

HT_API uint32 net_buf_idle_num()
{
	if (net_buf_fl == NULL)
	{
		return 0;
	}

	return net_buf_fl->node_num;
}

HT_API void net_buf_deinit()
{
	if (net_buf_fl)
	{
		pps_fl_free(net_buf_fl);
		net_buf_fl = NULL;
	}
}

HT_API BOOL hdrv_buf_init(int num)
{
	hdrv_buf_fl = pps_ctx_fl_init(num, sizeof(HDRV), TRUE);
	if (hdrv_buf_fl == NULL)
	{
		return FALSE;
	}

	log_print(HT_LOG_INFO, "%s, num = %lu\r\n", __FUNCTION__, hdrv_buf_fl->node_num);

	return TRUE;
}

HT_API void hdrv_buf_deinit()
{
	if (hdrv_buf_fl)
	{
		pps_fl_free(hdrv_buf_fl);
		hdrv_buf_fl = NULL;
	}
}

HT_API HDRV *hdrv_buf_get_idle()
{
	HDRV *p_ret = (HDRV *)pps_fl_pop(hdrv_buf_fl);

	return p_ret;
}

HT_API void hdrv_buf_free(HDRV *pHdrv)
{
	if (pHdrv == NULL)
	{
		return;
	}

	pHdrv->header[0] = '\0';
	pHdrv->value_string = NULL;

	pps_fl_push(hdrv_buf_fl, pHdrv);
}

HT_API uint32 hdrv_buf_idle_num()
{
	if (NULL == hdrv_buf_fl)
	{
		return 0;
	}

	return hdrv_buf_fl->node_num;
}

HT_API void hdrv_ctx_ul_init(PPSN_CTX *ul_ctx)
{
	pps_ctx_ul_init_nm(hdrv_buf_fl, ul_ctx);
}

HT_API void hdrv_ctx_free(PPSN_CTX *p_ctx)
{
	HDRV *p_free;

	if (p_ctx == NULL)
	{
		return;
	}

	p_free = (HDRV *)pps_lookup_start(p_ctx);
	while (p_free != NULL)
	{
		HDRV *p_next = (HDRV *)pps_lookup_next(p_ctx, p_free);

		pps_ctx_ul_del(p_ctx, p_free);
		hdrv_buf_free(p_free);

		p_free = p_next;
	}
	pps_lookup_end(p_ctx);
}

HT_API BOOL sys_buf_init(int nums)
{
	if (net_buf_init(nums, 2048) == FALSE)
	{
		log_print(HT_LOG_ERR, "%s, net_buf_init failed!!!\r\n", __FUNCTION__);
		return FALSE;
	}

	if (hdrv_buf_init(8 * nums) == FALSE)
	{
		log_print(HT_LOG_ERR, "%s, hdrv_buf_init failed!!!\r\n", __FUNCTION__);
		return FALSE;
	}

	return TRUE;
}

HT_API void sys_buf_deinit()
{
	net_buf_deinit();
	hdrv_buf_deinit();
}
int copySwapToYaml(const char *swapFilePath)
{
	// Check if input ends with .swp
	const char *ext = strrchr(swapFilePath, '.');
	if (!ext || strcmp(ext, ".swp") != 0)
	{
		printf("Not a valid .swp file: %s\n", swapFilePath);
		return -1;
	}

	// Build YAML file path
	char yamlFilePath[512];
	const char *filename = strrchr(swapFilePath, '/');
	if (!filename)
	{
		filename = swapFilePath;
	}
	else
	{
		filename++; // skip '/'
	}

	size_t dirLen = filename - swapFilePath;
	strncpy(yamlFilePath, swapFilePath, dirLen); // copy the directory
	yamlFilePath[dirLen] = '\0';

	strcat(yamlFilePath, filename + 1); // skip leading dot from swap file name

	// Remove ".swp"
	char *dotSwp = strrchr(yamlFilePath, '.');
	if (dotSwp)
	{
		*dotSwp = '\0';
	}

	// Open files
	FILE *src = fopen(swapFilePath, "r");
	if (!src)
	{
		perror("Failed to open swap file");
		return -1;
	}

	FILE *dest = fopen(yamlFilePath, "w");
	if (!dest)
	{
		perror("Failed to open destination file");
		fclose(src);
		return -1;
	}

	// Copy contents
	char buffer[1024];
	size_t n;
	while ((n = fread(buffer, 1, sizeof(buffer), src)) > 0)
	{
		fwrite(buffer, 1, n, dest);
	}

	fclose(src);
	fclose(dest);

	// Delete the swap file
	if (unlink(swapFilePath) == 0)
	{
		printf("Copied content and deleted swap file: %s\n", swapFilePath);
	}
	else
	{
		perror("Failed to delete swap file");
		return -1;
	}
	strcpy(swapFilePath, yamlFilePath);
	printf("Successfully updated YAML: %s\n", yamlFilePath);
	return 0;
}
//SOTERIX
HT_API void *sys_netplan_init(const char *configFilePath)
{
	char *directory = "/etc/netplan";
	DIR *dir;
	struct dirent *entry;
	char defaultConfigFilePath[512] = {'\0'};
	if ((dir = opendir(directory)) == NULL)
	{
		log_print(HT_LOG_WARN, "%s: directory %s not available\r\n",
				  __FUNCTION__, directory);

		return NULL;
	}
	while ((entry = readdir(dir)) != NULL)
	{
		// Check if the file has a ".yaml" extension and does not contain "wifi" in the name
		if (strstr(entry->d_name, ".yaml") != NULL && strstr(entry->d_name, "wifi") == NULL)
		{

			snprintf(defaultConfigFilePath, sizeof(defaultConfigFilePath), "%s/%s", directory, entry->d_name);
			break;
		}
	}

	printf("\n defaultConfigFilePath = %s", defaultConfigFilePath);

	// Use the default path if the provided path is NULL
	if (strlen(configFilePath) == 0 || configFilePath == NULL)
	{
		log_print(HT_LOG_WARN, "%s: configFilePath is NULL, using default: %s\r\n",
				  __FUNCTION__, defaultConfigFilePath);
		configFilePath = defaultConfigFilePath; // Assign default path
	}
	copySwapToYaml(configFilePath);

	void *manager = netplan_manager_create(configFilePath);
	if (!manager)
	{
		log_print(HT_LOG_ERR, "%s: Failed to create NetPlanManager instance.\r\n",
				  __FUNCTION__);
		return NULL;
	}

	return manager;
}

HT_API void sys_netplan_deinit(void *manager)
{
	netplan_manager_destroy(manager);
}
