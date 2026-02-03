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

void parseSentUsers(const char *request){
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

void delete_csv_line(){
    //
}

void update_csv_line(const char *request){
    //
    parseSentUsers(request);
}
#endif /*SET_DELETE_H */