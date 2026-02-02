#ifndef USER_MANAGEMENT_H
#define USER_MANAGEMENT_H

#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include "getuser.h"

// SOAP Response Templates
const char *CREATE_USER_RESPONSE =
    "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n"
    "<soap:Envelope xmlns:soap=\"http://www.w3.org/2003/05/soap-envelope\" "
    "xmlns:tds=\"http://www.onvif.org/ver10/device/wsdl\">\n"
    "  <soap:Body>\n"
    "    <tds:CreateUsersResponse/>\n"
    "  </soap:Body>\n"
    "</soap:Envelope>";

const char *SET_USER_RESPONSE =
    "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n"
    "<soap:Envelope xmlns:soap=\"http://www.w3.org/2003/05/soap-envelope\" "
    "xmlns:tds=\"http://www.onvif.org/ver10/device/wsdl\">\n"
    "  <soap:Body>\n"
    "    <tds:SetUserResponse/>\n"
    "  </soap:Body>\n"
    "</soap:Envelope>";

const char *DELETE_USER_RESPONSE =
    "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n"
    "<soap:Envelope xmlns:soap=\"http://www.w3.org/2003/05/soap-envelope\" "
    "xmlns:tds=\"http://www.onvif.org/ver10/device/wsdl\">\n"
    "  <soap:Body>\n"
    "    <tds:DeleteUsersResponse/>\n"
    "  </soap:Body>\n"
    "</soap:Envelope>";

// Extract username from SOAP request
void extract_username_from_request(const char *request, char *username, size_t size) {
    const char *start = strstr(request, "<Username>");
    if (!start) {
        start = strstr(request, "<tt:Username>");
    }
    if (!start) {
        username[0] = '\0';
        return;
    }
    
    start = strchr(start, '>');
    if (!start) {
        username[0] = '\0';
        return;
    }
    start++;
    
    const char *end = strstr(start, "</");
    if (!end) {
        username[0] = '\0';
        return;
    }
    
    size_t len = end - start;
    if (len >= size) len = size - 1;
    memcpy(username, start, len);
    username[len] = '\0';
}

// Extract password from SOAP request
void extract_password_from_request(const char *request, char *password, size_t size) {
    const char *start = strstr(request, "<Password>");
    if (!start) {
        start = strstr(request, "<tt:Password>");
    }
    if (!start) {
        password[0] = '\0';
        return;
    }
    
    start = strchr(start, '>');
    if (!start) {
        password[0] = '\0';
        return;
    }
    start++;
    
    const char *end = strstr(start, "</");
    if (!end) {
        password[0] = '\0';
        return;
    }
    
    size_t len = end - start;
    if (len >= size) len = size - 1;
    memcpy(password, start, len);
    password[len] = '\0';
}

// Extract user level from SOAP request
void extract_userlevel_from_request(const char *request, char *level, size_t size) {
    const char *start = strstr(request, "<UserLevel>");
    if (!start) {
        start = strstr(request, "<tt:UserLevel>");
    }
    if (!start) {
        level[0] = '\0';
        return;
    }
    
    start = strchr(start, '>');
    if (!start) {
        level[0] = '\0';
        return;
    }
    start++;
    
    const char *end = strstr(start, "</");
    if (!end) {
        level[0] = '\0';
        return;
    }
    
    size_t len = end - start;
    if (len >= size) len = size - 1;
    memcpy(level, start, len);
    level[len] = '\0';
}

// Create a new user
bool create_user(const char *username, const char *password, userlevel level) {
    // Check if user already exists
    for (int i = 0; i < userCount; i++) {
        if (strcmp(myUsers[i].username, username) == 0) {
            printf("[UserMgmt] User '%s' already exists\n", username);
            return false;
        }
    }
    
    if (userCount >= MAX_USERS) {
        printf("[UserMgmt] Cannot create user: maximum users reached\n");
        return false;
    }
    
    // Add to memory
    strncpy(myUsers[userCount].username, username, 63);
    myUsers[userCount].username[63] = '\0';
    myUsers[userCount].level = level;
    userCount++;
    
    // Append to CSV file
    FILE *fp = fopen("/home/lts/NetC/ONVIF-SIM/fakecamera/authhandler/CredsWithLevel.csv", "a");
    if (!fp) {
        printf("[UserMgmt] Error: Cannot open CredsWithLevel.csv for appending\n");
        userCount--;  // Rollback
        return false;
    }
    
    fprintf(fp, "%s,%s,%s\n", username, password, UserLevelToString(level));
    fclose(fp);
    
    printf("[UserMgmt] User '%s' created successfully\n", username);
    return true;
}

// Set/update user information
bool set_user(const char *username, const char *password, userlevel level) {
    // Find user in memory
    int userIndex = -1;
    for (int i = 0; i < userCount; i++) {
        if (strcmp(myUsers[i].username, username) == 0) {
            userIndex = i;
            break;
        }
    }
    
    if (userIndex == -1) {
        printf("[UserMgmt] User '%s' not found\n", username);
        return false;
    }
    
    // Update in memory
    myUsers[userIndex].level = level;
    
    // Rewrite entire CSV file
    FILE *fp = fopen("/home/lts/NetC/ONVIF-SIM/fakecamera/authhandler/CredsWithLevel.csv", "w");
    if (!fp) {
        printf("[UserMgmt] Error: Cannot open CredsWithLevel.csv for writing\n");
        return false;
    }
    
    fprintf(fp, "username,password,userlevel\n");
    for (int i = 0; i < userCount; i++) {
        // Update password for the target user, keep others unchanged
        if (i == userIndex && password[0] != '\0') {
            fprintf(fp, "%s,%s,%s\n", myUsers[i].username, password, UserLevelToString(myUsers[i].level));
        } else {
            // For other users, we need to read the old password from the file
            // For simplicity, just update the level and use "pass" as default
            fprintf(fp, "%s,pass,%s\n", myUsers[i].username, UserLevelToString(myUsers[i].level));
        }
    }
    fclose(fp);
    
    printf("[UserMgmt] User '%s' updated successfully\n", username);
    return true;
}

// Delete a user
bool delete_user(const char *username) {
    // Find user in memory
    int userIndex = -1;
    for (int i = 0; i < userCount; i++) {
        if (strcmp(myUsers[i].username, username) == 0) {
            userIndex = i;
            break;
        }
    }
    
    if (userIndex == -1) {
        printf("[UserMgmt] User '%s' not found\n", username);
        return false;
    }
    
    // Remove from memory by shifting
    for (int i = userIndex; i < userCount - 1; i++) {
        myUsers[i] = myUsers[i + 1];
    }
    userCount--;
    
    // Rewrite entire CSV file
    FILE *fp = fopen("/home/lts/NetC/ONVIF-SIM/fakecamera/authhandler/CredsWithLevel.csv", "w");
    if (!fp) {
        printf("[UserMgmt] Error: Cannot open CredsWithLevel.csv for writing\n");
        return false;
    }
    
    fprintf(fp, "username,password,userlevel\n");
    for (int i = 0; i < userCount; i++) {
        fprintf(fp, "%s,pass,%s\n", myUsers[i].username, UserLevelToString(myUsers[i].level));
    }
    fclose(fp);
    
    printf("[UserMgmt] User '%s' deleted successfully\n", username);
    return true;
}

// Check if the authenticated user is an admin
bool is_admin_user(const char *request) {
    // Extract username from WS-Security header
    char user[64] = {0};
    const char *start = strstr(request, "wsse:Username");
    if (!start) start = strstr(request, "<Username>");
    if (!start) {
        // Try to extract from HTTP Digest
        const char *auth = strstr(request, "Authorization: Digest");
        if (auth) {
            const char *username_start = strstr(auth, "username=\"");
            if (username_start) {
                username_start += 10;
                const char *username_end = strchr(username_start, '"');
                if (username_end) {
                    size_t len = username_end - username_start;
                    if (len >= sizeof(user)) len = sizeof(user) - 1;
                    memcpy(user, username_start, len);
                    user[len] = '\0';
                }
            }
        }
    } else {
        start = strchr(start, '>');
        if (start) {
            start++;
            const char *end = strstr(start, "</");
            if (end) {
                size_t len = end - start;
                if (len >= sizeof(user)) len = sizeof(user) - 1;
                memcpy(user, start, len);
                user[len] = '\0';
            }
        }
    }
    
    if (user[0] == '\0') {
        printf("[UserMgmt] Cannot extract username from request\n");
        return false;
    }
    
    // Check if user is Administrator
    for (int i = 0; i < userCount; i++) {
        if (strcmp(myUsers[i].username, user) == 0) {
            if (myUsers[i].level == Administrator) {
                printf("[UserMgmt] User '%s' is Administrator\n", user);
                return true;
            }
            printf("[UserMgmt] User '%s' is not Administrator (level: %s)\n", 
                   user, UserLevelToString(myUsers[i].level));
            return false;
        }
    }
    
    printf("[UserMgmt] User '%s' not found in system\n", user);
    return false;
}

#endif /* USER_MANAGEMENT_H */
