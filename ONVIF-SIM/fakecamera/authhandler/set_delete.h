#ifndef SET_DELETE_H
#define SET_DELETE_H

#include <stddef.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
// this file has all the update and delete csv line functions

#define MAXUSERSADD 20
#define MAXLENADD 512

typedef struct {
    char username[MAXLENADD];
    char password[MAXLENADD];
    char userLevel[MAXLENADD];
} UserCredsupdate;

typedef struct {
    char username[MAXLENADD];
}usersdelarr;

int extract_tag_setdel(const char *sourceCursor, const char *startTag, const char *endTag, char *destinationArray) {
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
static int numofuserssentdelete = 0;
// need to find better logic later for num of users sent
// the design needs to be clever as to parse efficiently
static UserCredsupdate usersadd[] = {0};
static usersdelarr usersdelarray[] = {0};

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
        extract_tag_setdel(movingCursor, "<tt:Username>", "</tt:Username>", usersadd[numofuserssentupdate].username);

        // Extract Password
        extract_tag_setdel(movingCursor, "<tt:Password>", "</tt:Password>", usersadd[numofuserssentupdate].password);

        // Extract UserLevel
        extract_tag_setdel(movingCursor, "<tt:UserLevel>", "</tt:UserLevel>", usersadd[numofuserssentupdate].userLevel);
        numofuserssentupdate++; // last marked point
        // below is pointer arithmetic to move the pointer to later
        movingCursor = userEnd + strlen("</tds:User>");// <-- ADDED
    }
}

// Parse <DeleteUsers> (List of <Username>), a bit modified
void parse_delete_users_xml(const char *request) {
    numofuserssentdelete = 0;
    const char *cursor = request;

    // Loop for <tt:Username> so
    while (cursor && numofuserssentdelete < MAXUSERSADD) {

        // start tag
        const char *tagStart = strstr(cursor, "<tt:Username>");
        if (!tagStart) break;

        // Extract
        if (extract_tag_setdel(cursor, "<tt:Username>", "</tt:Username>", usersdelarray[numofuserssentdelete].username)) {
            numofuserssentdelete++;
        }

        // mov cursor manually past the END tag, similar as above but at end
        // yup will see if it sticks or not
        const char *tagEnd = strstr(tagStart, "</tt:Username>");
        if (!tagEnd) break;

        cursor = tagEnd + strlen("</tt:Username>");
    }
}

void setuserscsv(){
    //FILE *fp = fopen("CredsWithLevel.csv","w");
    // ok so i know for fact that mutex locks in cs and commit rollback in db
    // exists for a reason maybe so directly writing in main file is not healthy
    // so temporary file? need to know about like some txt or some os specific
    // temp kindof file format exist? like whenever its been pointed os will
    // not auto remove it, yes it exist in windows and unix based systems
    // though linux is different than unix, todo create header handling this
    FILE *fp = fopen("CredsWithLevel.csv", "r");
    if (!fp) {
        perror("CredsWithLevel.csv");
        return;
    }

    // Create memory stream for new content
    char *buffer = NULL;
    size_t size = 0;
    FILE *memstream = open_memstream(&buffer, &size);
    if (!memstream) {
        perror("open_memstream");
        fclose(fp);
        return;
    }

    // Read and process CSV line by line
    char line[5120];
    while (fgets(line, sizeof(line), fp)) {
        fprintf(memstream, "%s", line);
    }
    // forgot this step critical
    for (int i = 0; i < numofuserssentupdate; i++) {
        fprintf(memstream, "%s,%s,%s\n", 
            usersadd[i].username, 
            usersadd[i].password, 
            usersadd[i].userLevel);
    }

    // Reset the counter
    numofuserssentupdate = 0;

    fclose(fp);
    fclose(memstream);

    // Write to temp file
    FILE *fptmp = fopen("CredsWithLevel.tmp", "w");
    if (!fptmp) {
        perror("CredsWithLevel.tmp");
        free(buffer);
        return;
    }

    if (fprintf(fptmp, "%s", buffer) < 0) {
        perror("Failed to write to temp file");
        fclose(fptmp);
        unlink("CredsWithLevel.tmp");
        free(buffer);
        return;
    }

    fflush(fptmp);
    int fd = fileno(fptmp);
    fsync(fd);
    fclose(fptmp);

    // Atomic rename, from 'acid' 'a' i guess
    if (rename("CredsWithLevel.tmp", "CredsWithLevel.csv") != 0) {
        perror("Failed to rename temp file");
        unlink("CredsWithLevel.tmp");
        free(buffer);
        return;
    }

    free(buffer);
}

// need to modify the whole impl logic to accomodate series of del users
void deluserscsv(const char *username_todel) {
    FILE *fp = fopen("CredsWithLevel.csv", "r");
    if (!fp) {
        perror("CredsWithLevel.csv");
        return;
    }
    
    char *buffer = NULL;
    size_t size = 0;
    FILE *memstream = open_memstream(&buffer, &size);
    if (!memstream) {
        perror("open_memstream");
        fclose(fp);
        return;
    }
    
    // Read header line first
    char header[1024];
    if (fgets(header, sizeof(header), fp)) {
        fprintf(memstream, "%s", header); // Always keep header
    }
    
    // Process data lines, skipping the one to delete
    char line[1024];
    int found = 0;
    while (fgets(line, sizeof(line), fp)) {
        // Parse username from line (assuming format: username,password,level)
        char username[256];
        if (sscanf(line, "%255[^,]", username) == 1) {
            if (strcmp(username, username_todel) == 0) {
                found = 1;
                continue; // Skip this user no copy
            }
        }
        fprintf(memstream, "%s", line); // keep all other lines
    }
    
    fclose(fp);
    fclose(memstream);
    
    if (!found) {
        printf("User '%s' not found\n", username_todel);
        free(buffer);
        return;
    }
    
    // Rest of same...
    FILE *fptmp = fopen("CredsWithLevel.tmp", "w");
    if (!fptmp) {
        perror("CredsWithLevel.tmp");
        free(buffer);
        return;
    }
    
    if (fprintf(fptmp, "%s", buffer) < 0) {
        perror("Failed to write to temp file");
        fclose(fptmp);
        unlink("CredsWithLevel.tmp");
        free(buffer);
        return;
    }
    
    fflush(fptmp);
    int fd = fileno(fptmp);
    fsync(fd);
    fclose(fptmp);
    
    if (rename("CredsWithLevel.tmp", "CredsWithLevel.csv") != 0) {
        perror("Failed to rename temp file");
        unlink("CredsWithLevel.tmp");
        free(buffer);
        return;
    }
    
    free(buffer);
    printf("User '%s' deleted successfully\n", username_todel);
}

#endif /*SET_DELETE_H */
