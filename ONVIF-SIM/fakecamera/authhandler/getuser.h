#ifndef GETUSER_H
#define GETUSER_H

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#define MAX_USERS 100

typedef enum{
    Administrator,
    Operator,
    User,
    Anonymous,
    Extended
}userlevel;

typedef struct {
    char username[64];
    userlevel level;
} DeviceUser;

const char* UserLevelToString(userlevel level) {
    switch(level) {
        case Administrator: return "Administrator";
        case Operator: return "Operator";
        case User: return "User";
        case Anonymous: return "Anonymous";
        case Extended: return "Extended";
        default: return "Unknown";
    }
}

//enum returning function
userlevel StringToUserLevel(const char* str) {
    if (strcmp(str, "Administrator") == 0) return Administrator;
    if (strcmp(str, "Operator") == 0) return Operator;
    if (strcmp(str, "User") == 0) return User;
    if (strcmp(str, "Anonymous") == 0) return Anonymous;
    if (strcmp(str, "Extended") == 0) return Extended;
    return User; // default
}

// so i need to fetch all the user list
// only under the admin user level tag
// and each entity shoud have
// username and userlevel
// 1. The Start of the SOAP Envelope
const char *SOAP_HEADER =
    "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n"
    "<soap:Envelope xmlns:soap=\"http://www.w3.org/2003/05/soap-envelope\" "
    "xmlns:tds=\"http://www.onvif.org/ver10/device/wsdl\">\n"
    "  <soap:Body>\n"
    "    <tds:GetUsersResponse>\n";

// 2. The Template for ONE User as its dynamic need many
// Formats: %s = Username, %s = UserLevel String
const char *USER_NODE_TEMPLATE =
    "      <tds:User>\n"
    "        <tds:Username>%s</tds:Username>\n"
    "        <tds:UserLevel>%s</tds:UserLevel>\n"
    "      </tds:User>\n";

// 3. The End of the SOAP Envelope, duh!
const char *SOAP_FOOTER =
    "    </tds:GetUsersResponse>\n"
    "  </soap:Body>\n"
    "</soap:Envelope>";

static int userCount = 0;
static DeviceUser myUsers[MAX_USERS];

void loadUsers() {
    FILE *fp = fopen("CredsWithLevel.csv", "r");
    if (!fp) {
        perror("CredsWithLevels");
        return;
    }

    char line[256]; // i guess its enough
    userCount = 0;
    fgets(line, sizeof(line), fp);  // Skip header

    while (fgets(line, sizeof(line), fp) && userCount < MAX_USERS) {
        line[strcspn(line, "\r\n")] = 0;  // <-- ADDED
        char *username = strtok(line, ",");
        char *password = strtok(NULL, ",");
        char *level = strtok(NULL, ",\r\n");  // <-- CHANGED: Added delimiters

        if (username && level) {// leaving out pass as its optional in convention
            // Trim whitespace from level  // <-- ADDED: Fix spaces
            while (*level == ' ' || *level == '\t') level++;  // <-- ADDED
            strncpy(myUsers[userCount].username, username, 63);
            myUsers[userCount].username[63] = '\0';  // <-- ADDED: Null terminate
            myUsers[userCount].level = StringToUserLevel(level);
            userCount++;
        }
    }

    fclose(fp);
}

// abstracted away the working of offset in modular way
static void append(char **p, int *rem, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(*p, *rem, fmt, ap);
    va_end(ap);
    *p += n;
    *rem -= n;
}

void GenerateGetUsersResponse(char *p, int maxLen) {
    //char *p = buffer;
    // will be 3 appends as the structure demands
    int rem = maxLen;

    append(&p, &rem, "%s", SOAP_HEADER);

    for (int i = 0; i < userCount; i++) {
        append(&p, &rem,
               USER_NODE_TEMPLATE,
               myUsers[i].username,
               UserLevelToString(myUsers[i].level));
    }

    append(&p, &rem, "%s", SOAP_FOOTER);
}


void GenerateGetUsersResponse1(char* buffer, int maxLen) {
    int offset = 0;

    // 1. Append Header
    offset += snprintf(buffer + offset, maxLen - offset, "%s", SOAP_HEADER);

    // 2. Loop through users and Append using the TEMPLATE
    for (int i = 0; i < userCount; i++) {
        const char* levelStr = UserLevelToString(myUsers[i].level);

        // multiple user
        offset += snprintf(buffer + offset, maxLen - offset,
                           USER_NODE_TEMPLATE,
                           myUsers[i].username,
                           levelStr);
    }

    // 3. Append Footer
    offset += snprintf(buffer + offset, maxLen - offset, "%s", SOAP_FOOTER);
}
#endif /* GETUSER_H */
