#include <stdio.h>
#include <sys/time.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <ctype.h>
#include <sys/stat.h>
#include "config.h"

// Function to generate a 16-byte ID based on time in microseconds
void generate_16byte_id(uint8_t *id)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);

    // Combine seconds and microseconds into a 64-bit integer
    uint64_t time_in_microseconds = (uint64_t)tv.tv_sec * 1000000 + (uint64_t)tv.tv_usec;

    // Fill the first 8 bytes with the timestamp in microseconds
    id[0] = (time_in_microseconds >> 56) & 0xFF;
    id[1] = (time_in_microseconds >> 48) & 0xFF;
    id[2] = (time_in_microseconds >> 40) & 0xFF;
    id[3] = (time_in_microseconds >> 32) & 0xFF;
    id[4] = (time_in_microseconds >> 24) & 0xFF;
    id[5] = (time_in_microseconds >> 16) & 0xFF;
    id[6] = (time_in_microseconds >> 8) & 0xFF;
    id[7] = time_in_microseconds & 0xFF;

    // Use random numbers to fill the remaining 5 bytes
    srand(time(NULL)); // Seed random number generator with the current time
    for (int i = 8; i < 16; ++i)
    {
        id[i] = rand() & 0xFF; // Generate a random byte
    }
}

// Function to check if UUID is already in the file
int is_uuid_present_in_file()
{
    const char *filename = CNF_SERIAL_PATH;
    FILE *file = fopen(filename, "r");

    if (file == NULL)
    {
        // File doesn't exist or can't be opened, treat as if UUID is not present
        return 0;
    }

    char line[256];
    while (fgets(line, sizeof(line), file))
    {
        if (strstr(line, "VTPL_VSAAS_UNIQUE_ID=") != NULL)
        {
            // UUID is present in the file
            fclose(file);
            return 1;
        }
    }

    fclose(file);
    return 0;
}
void formattedIdPrint(const uint8_t *id) {
    printf("\033[1;32m");
    printf("******************************************************************\n");
    printf("*                                                                *\n");
    printf("*  EDGE BOX SERIAL NUMBER : ");

    for (int i = 0; i < 16; ++i) {
        printf("%02X", id[i]);
        if ((i + 1) % 4 == 0 && i != 15) {
            printf("-");
        }
    }

    printf("  *\n");
    printf("*                                                                *\n");
    printf("******************************************************************\n");
    printf("\033[0m");
}

// Function to write the 16-byte ID in the 8-8-8-8 format with uppercase
void format_and_write_to_file(const uint8_t *id)
{
    const char *filename = CNF_SERIAL_PATH;
    FILE *file = fopen(filename, "w+");

    if (file == NULL)
    {
        fprintf(stderr, "Failed to open file: %s\n", filename);
        exit(EXIT_FAILURE);
    }

    // Write the 16-byte ID in uppercase and 8-8-8-8 format
    fprintf(file, "VTPL_VSAAS_UNIQUE_ID=");
    for (int i = 0; i < 16; ++i)
    {
        fprintf(file, "%02X", id[i]); // Print in uppercase
        // Add a dash (-) after every 4 characters
        if ((i + 1) % 4 == 0 && i != 15)
        {
            fprintf(file, "-");
        }
    }
    fprintf(file, "\n");

    // Write NULL placeholders for other variables
    // fprintf(file, "VTPL_VSAAS_DOMAIN=\n");
    // fprintf(file, "VTPL_VSAAS_USER_ID=\n");
    // fprintf(file, "VTPL_VSAAS_PD=\n");

    // Close the file
    fclose(file);
    // printf("Configuration written to %s\n", filename);
}

int main()
{
    // Check if UUID is already present in the file
    if (is_uuid_present_in_file())
    {
        printf("UUID already present in the file. No changes made.\n");
        return 0;
    }

    // Ensure output directory exists
    struct stat st = {0};
    if (stat("vtpl_cnf", &st) == -1) {
        mkdir("vtpl_cnf", 0700);
    }

    uint8_t id[16]; // 16-byte ID

    // Generate a 16-byte ID based on microsecond precision timestamp
    generate_16byte_id(id);

    // Format the ID and write to file
    format_and_write_to_file(id);

    formattedIdPrint(id);

    return 0;
}
