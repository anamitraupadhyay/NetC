#ifndef USER_MANAGEMENT_H
#define USER_MANAGEMENT_H

#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include "getuser.h"

// Extended structure to store password temporarily
typedef struct {
    char username[64];
    char password[64];
    userlevel level;
} UserWithPassword;

// SOAP Response Templates
static const char *CREATE_USER_RESPONSE =
    "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n"
    "<soap:Envelope xmlns:soap=\"http://www.w3.org/2003/05/soap-envelope\" "
    "xmlns:tds=\"http://www.onvif.org/ver10/device/wsdl\">\n"
    "  <soap:Body>\n"
    "    <tds:CreateUsersResponse/>\n"
    "  </soap:Body>\n"
    "</soap:Envelope>";

static const char *SET_USER_RESPONSE =
    "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n"
    "<soap:Envelope xmlns:soap=\"http://www.w3.org/2003/05/soap-envelope\" "
    "xmlns:tds=\"http://www.onvif.org/ver10/device/wsdl\">\n"
    "  <soap:Body>\n"
    "    <tds:SetUserResponse/>\n"
    "  </soap:Body>\n"
    "</soap:Envelope>";

static const char *DELETE_USER_RESPONSE =
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

// Load all users with passwords from CSV
int load_users_with_passwords(UserWithPassword *users, int max_users) {
    FILE *fp = fopen("authhandler/CredsWithLevel.csv", "r");
    if (!fp) {
        return 0;
    }
    
    char line[256];
    int count = 0;
    if (!fgets(line, sizeof(line), fp)) {  // Skip header - check return value
        fclose(fp);
        return 0;
    }
    
    while (fgets(line, sizeof(line), fp) && count < max_users) {
        line[strcspn(line, "\r\n")] = 0;
        char *username = strtok(line, ",");
        char *password = strtok(NULL, ",");
        char *level = strtok(NULL, ",\r\n");
        
        if (username && password && level) {
            while (*level == ' ' || *level == '\t') level++;
            strncpy(users[count].username, username, sizeof(users[count].username) - 1);
            users[count].username[sizeof(users[count].username) - 1] = '\0';
            strncpy(users[count].password, password, sizeof(users[count].password) - 1);
            users[count].password[sizeof(users[count].password) - 1] = '\0';
            users[count].level = StringToUserLevel(level);
            count++;
        }
    }
    
    fclose(fp);
    return count;
}

// Save all users with passwords to CSV
bool save_users_to_csv(UserWithPassword *users, int count) {
    FILE *fp = fopen("authhandler/CredsWithLevel.csv", "w");
    if (!fp) {
        printf("[UserMgmt] Error: Cannot open CredsWithLevel.csv for writing\n");
        return false;
    }
    
    fprintf(fp, "username,password,userlevel\n");
    for (int i = 0; i < count; i++) {
        fprintf(fp, "%s,%s,%s\n", users[i].username, users[i].password, UserLevelToString(users[i].level));
    }
    fclose(fp);
    return true;
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
    strncpy(myUsers[userCount].username, username, sizeof(myUsers[userCount].username) - 1);
    myUsers[userCount].username[sizeof(myUsers[userCount].username) - 1] = '\0';
    myUsers[userCount].level = level;
    userCount++;
    
    // Append to CSV file
    FILE *fp = fopen("authhandler/CredsWithLevel.csv", "a");
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
    // Load all users with passwords
    UserWithPassword users[MAX_USERS];
    int count = load_users_with_passwords(users, MAX_USERS);
    
    // Find user
    int userIndex = -1;
    for (int i = 0; i < count; i++) {
        if (strcmp(users[i].username, username) == 0) {
            userIndex = i;
            break;
        }
    }
    
    if (userIndex == -1) {
        printf("[UserMgmt] User '%s' not found\n", username);
        return false;
    }
    
    // Update user info
    if (password[0] != '\0') {
        strncpy(users[userIndex].password, password, sizeof(users[userIndex].password) - 1);
        users[userIndex].password[sizeof(users[userIndex].password) - 1] = '\0';
    }
    users[userIndex].level = level;
    
    // Save back to file
    if (!save_users_to_csv(users, count)) {
        return false;
    }
    
    // Update in-memory user list (myUsers)
    for (int i = 0; i < userCount; i++) {
        if (strcmp(myUsers[i].username, username) == 0) {
            myUsers[i].level = level;
            break;
        }
    }
    
    printf("[UserMgmt] User '%s' updated successfully\n", username);
    return true;
}

// Delete a user
bool delete_user(const char *username) {
    // Load all users with passwords
    UserWithPassword users[MAX_USERS];
    int count = load_users_with_passwords(users, MAX_USERS);
    
    // Find user to delete
    int userIndex = -1;
    for (int i = 0; i < count; i++) {
        if (strcmp(users[i].username, username) == 0) {
            userIndex = i;
            break;
        }
    }
    
    if (userIndex == -1) {
        printf("[UserMgmt] User '%s' not found\n", username);
        return false;
    }
    
    // Remove user by shifting array
    for (int i = userIndex; i < count - 1; i++) {
        users[i] = users[i + 1];
    }
    count--;
    
    // Save back to file
    if (!save_users_to_csv(users, count)) {
        return false;
    }
    
    // Update in-memory user list (myUsers)
    for (int i = 0; i < userCount; i++) {
        if (strcmp(myUsers[i].username, username) == 0) {
            // Shift users in memory
            for (int j = i; j < userCount - 1; j++) {
                myUsers[j] = myUsers[j + 1];
            }
            userCount--;
            break;
        }
    }
    
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
