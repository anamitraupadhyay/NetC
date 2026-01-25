#include <stdint.h>
#include <uchar.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

typedef struct {
    uint16_t server_port;
    char manufacturer[64];
    char model[64];
    float firmware_version;
    char serial_number[32];
    float hardware_id;
} datafromxml;


static inline uint8_t get_the_tag(
    const char *line, // the buffer line to read from
    const char *tag, // xml tag <%s> and </%s> and %s is server_id
    char *out, // the output buffer as inited from the calling function
    size_t out_size // the output size of buf
){
    char open[64], close[64];
    snprintf(open, sizeof(open), "<%s>", tag);
    snprintf(close, sizeof(close), "</%s>", tag);
    // set from tag both opened and closed, no need for closed tag input duh!
    const char *start = strstr(line, open);
    if (!start) return 0;
    
    start += strlen(open);
    
    const char *end = strstr(start, close);
    if (!end) return 0;
    
    size_t len = end - start;
    if (len >= out_size) len = out_size - 1;
    
    memcpy(out, start, len);
    out[len] = '\0';
    
    return 1;
}

int load_config(const char *filename, datafromxml *cfg)
{
    FILE *fp = fopen(filename, "r");
    if (!fp) return 0;

    char line[256];
    char buf[128];

    while (fgets(line, sizeof(line), fp)) {

        if (get_the_tag(line, "server_port", buf, sizeof(buf)))
            cfg->server_port = (uint16_t)atoi(buf);

        else if (get_the_tag(line, "manufacturer", cfg->manufacturer,
                                   sizeof(cfg->manufacturer)));
            

        else if (get_the_tag(line, "model", 
                                    cfg->model,
                                    sizeof(cfg->model)));
            

        else if (get_the_tag(line, "firmware_version", buf, sizeof(buf)))
            cfg->firmware_version = (float)atof(buf);

        else if (get_the_tag(line, "serial_number",
                                   cfg->serial_number,
                                   sizeof(cfg->serial_number)));
            

        else if (get_the_tag(line, "hardware_id", buf,sizeof(buf)))
            cfg->hardware_id = (float)atoi(buf);
    }

    fclose(fp);
    return 1;
}

int main(void)
{
    datafromxml cfg = {0};

    if (!load_config("config.xml", &cfg)) {
        printf("Failed to load config\n");
        return 1;
    }

    printf("Port: %d\n", cfg.server_port);
    printf("Manufacturer: %s\n", cfg.manufacturer);
    printf("Model: %s\n", cfg.model);
    printf("Firmware: %f\n", cfg.firmware_version);
    printf("Serial: %s\n", cfg.serial_number);
    printf("HW ID: %f\n", cfg.hardware_id);
}