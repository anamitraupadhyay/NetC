#ifndef SET_DELETE_H
#define SET_DELETE_H

#include <string.h>
#include <stdio.h>
// this file has all the update and delete csv line functions

#define MAXUSERSADD 20
#define MAXLENADD 512

typedef struct {
    char username[MAXLENADD];
    char password[MAXLENADD];
    char userLevel[MAXLENADD];
} UserCredsupdate;

int extract_tag(const char *sourceCursor, const char *startTag, const char *endTag, char *destinationArray) {
    const char *start = strstr(sourceCursor, startTag);
    if (!start) return 0;
    
    // Move pointer to the end of the start tag
    start += strlen(startTag);
    
    const char *end = strstr(start, endTag);
    if (!end) return 0;
    
    // Calculate length of the value
    long length = end - start;
    if (length >= MAXLENADD) length = MAXLENADD - 1; // Safety cap
    
    strncpy(destinationArray, start, length);
    destinationArray[length] = '\0'; // Ensure null-termination
    
    return 1;
}

static int numofuserssentupdate = 0;
// need to find better logic later for num of users sent
// the design needs to be clever as to parse efficiently 
static UserCredsupdate usersadd[] = {0};

void parseSetUsers(const char *request){
    //const char *start = strstr(request,"<tds:CreateUsers>");
    //const char *end = strstr(request, "</tds:CreateUsers>");
    const char *movingCursor = request;// points to baseaddr
    
    // as per llm "request" is passed in while loop
    // due to which its starting from start
    // do movingCursor as its getting updated each loop 
    while((movingCursor = strstr(/*request*/movingCursor, "<tds:User>")) != NULL){
        if(numofuserssentupdate >= MAXUSERSADD){
            printf("for now due to poor design choice the hardcoded buffer size %d overflows\n", numofuserssentupdate); break;
        }
        // experimenting with design choices here by using
        // temporary pointers so we only search inside the current User block
        // end of this specific user block to limit search scope
        const char *userEnd = strstr(movingCursor, "</tds:User>");
        if (!userEnd) break; 

        // Extract Username
        extract_tag(movingCursor, "<tt:Username>", "</tt:Username>", usersadd[numofuserssentupdate].username);
        
        // Extract Password
        extract_tag(movingCursor, "<tt:Password>", "</tt:Password>", usersadd[numofuserssentupdate].password);
        
        // Extract UserLevel
        extract_tag(movingCursor, "<tt:UserLevel>", "</tt:UserLevel>", usersadd[numofuserssentupdate].userLevel);
        numofuserssentupdate++; // last marked point
        // below is pointer arithmetic to move the pointer to later
        movingCursor = userEnd + strlen("</tds:User>");// <-- ADDED
    }
}

// Parse <DeleteUsers> (List of <Username>)
void parse_delete_users_xml(const char *request) {
    numofuserssentupdate = 0;
    const char *cursor = request;
    
    // ONVIF DeleteUsers usually looks like: <tds:Username>Name</tds:Username>
    // Sometimes namespaced differently, we'll try generic match
    while ((cursor = strstr(cursor, "Username>")) != NULL) {
        if (numofuserssentupdate >= MAXUSERSADD) break;
        
        // Backtrack to find start bracket '<' to ensure it's a tag
        const char *tagStart = cursor - 1;
        while (*tagStart != '<' && tagStart > request) tagStart--;

        // Check if it is a closing tag, if so skip
        if (*(tagStart + 1) == '/') {
            cursor += 9; // Skip "Username>"
            continue;
        }

        const char *valStart = strchr(cursor, '>');
        if (!valStart) break; 
        valStart++; // Move past '>'

        const char *valEnd = strstr(valStart, "</");
        if (!valEnd) break;

        long len = valEnd - valStart;
        if (len >= MAXLENADD) len = MAXLENADD - 1;
        
        strncpy(usersadd[numofuserssentupdate].username, valStart, len);
        usersadd[numofuserssentupdate].username[len] = '\0';
        
        numofuserssentupdate++;
        cursor = valEnd + 2; 
    }
}
#endif /*SET_DELETE_H */