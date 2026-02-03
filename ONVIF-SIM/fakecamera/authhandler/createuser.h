//#include "getuser.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#define MAX_USERS1 20
#define MAXFIELD_LEN 512

typedef struct {
    char username[MAXFIELD_LEN];
    char password[MAXFIELD_LEN];
    char userLevel[MAXFIELD_LEN];
} UserCreds;

static int numofuserssent = 0;
// need to find better logic later for num of users sent
// the design needs to be clever as to parse efficiently 
static UserCreds users[MAX_USERS1] = {0};

void parseSentUsers(const char *request);
void appendusers(const char *request);
int extract_tag(const char *source, const char *startTag, 
    const char *endTag, char *destination);
void appendToCSV();


void parseSentUsers(const char *request){
    //const char *start = strstr(request,"<tds:CreateUsers>");
    //const char *end = strstr(request, "</tds:CreateUsers>");
    const char *movingCursor = request;// points to baseaddr
    
    while((movingCursor = strstr(request, "<tds:User>")) != NULL){
        if(numofuserssent >= MAX_USERS1){
            printf("for now due to poor design choice the hardcoded buffer size %d overflows\n", numofuserssent); break;
        }
        // experimenting with design choices here by using
        // temporary pointers so we only search inside the current User block
        // end of this specific user block to limit search scope
        const char *userEnd = strstr(movingCursor, "</tds:User>");
        if (!userEnd) break; 

        // Extract Username
        extract_tag(movingCursor, "<tt:Username>", "</tt:Username>", users[numofuserssent].username);
        
        // Extract Password
        extract_tag(movingCursor, "<tt:Password>", "</tt:Password>", users[numofuserssent].password);
        
        // Extract UserLevel
        extract_tag(movingCursor, "<tt:UserLevel>", "</tt:UserLevel>", users[numofuserssent].userLevel);
        numofuserssent++; // last marked point
        // below is pointer arithmetic to move the pointer to later
        movingCursor = userEnd + strlen("</tds:User>");// <-- ADDED
    }
}


void appendusers(const char *request) {
    // 1. Reset count necessary its a global var
    // and the improved design hasnt been applied yet
    numofuserssent = 0; 
    
    // 2. Parse the XML
    parseSentUsers(request);
    
    // 3. Add the users to CredsWithLevel.csv
    appendToCSV();
}

// ----------------
// Helper function to extract text between two tags
// Returns 1 if successful, 0 if not found
int extract_tag(const char *sourceCursor, const char *startTag, const char *endTag, char *destinationArray) {
    const char *start = strstr(sourceCursor, startTag);
    if (!start) return 0;
    
    // Move pointer to the end of the start tag
    start += strlen(startTag);
    
    const char *end = strstr(start, endTag);
    if (!end) return 0;
    
    // Calculate length of the value
    long length = end - start;
    if (length >= MAXFIELD_LEN) length = MAXFIELD_LEN - 1; // Safety cap
    
    strncpy(destinationArray, start, length);
    destinationArray[length] = '\0'; // Ensure null-termination
    
    return 1;
}

void appendToCSV() {
    FILE *fp = fopen("CredsWithLevel.csv", "a");
    if (fp == NULL) {
        perror("Error opening file");
        return;
    }
    // find the last line and then append
    // have to handle if csv doesnt end with \n
    
    for (int i = 0; i < numofuserssent; i++) { 
        // did here maxuser macro
        // and due to ongoig bug, num
        // is going inifinitly on one
        // name or tag only and appending it
        // and due to mismatch of uses it gave seg fault
        // and the file is not appending from next line even
        
        fprintf(fp, "%s,%s,%s\n", // not "%s,%s,%s,\n"
                users[i].username, 
                users[i].password, 
                users[i].userLevel);
    }

    fclose(fp);
    printf("{debug}appended %d users to CredsWithLevel.csv\n", numofuserssent);
}