#ifndef SET_DELETE_H
#define SET_DELETE_H

#include <netdb.h>
#include <arpa/inet.h>
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
        const char *tagStart = strstr(cursor, "<tds:Username>");
        if (!tagStart) break;

        // Extract
        if (extract_tag_setdel(cursor, "<tds:Username>", "</tds:Username>", usersdelarray[numofuserssentdelete].username)) {
            numofuserssentdelete++;
        }

        // mov cursor manually past the END tag, similar as above but at end
        // yup will see if it sticks or not
        const char *tagEnd = strstr(tagStart, "</tds:Username>");
        if (!tagEnd) break;

        cursor = tagEnd + strlen("</tds:Username>");
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
    char line[5120];// below jumps the header
    while (fgets(line, sizeof(line), fp)) {
        fprintf(memstream, "%s", line);
    }
   // main loop as the check is not here so it passed well
   // maybe later the check and other checks will be implemented here
   // so that time complexity will be less
   while(fgets(line, sizeof(line), fp)){
       char file_user[256];
       // Parse up to the first comma to get the username
       // Note: We use a temp buffer to avoid modifying 'line' in case we need to write it back
       if (sscanf(line, "%255[^,]", file_user) == 1) {
           
           // Check if this file_user is one of the users we need to update
           int match_index = -1;
           for (int i = 0; i < numofuserssentupdate; i++) {
               if (strcmp(file_user, usersadd[i].username) == 0) {
                   match_index = i;
                   break;
               }
           }

           if (match_index != -1) {
               // FOUND MATCH: Write the NEW data instead of the old line
               fprintf(memstream, "%s,%s,%s\n", 
                   usersadd[match_index].username, 
                   usersadd[match_index].password, 
                   usersadd[match_index].userLevel);
               
               // just continue as yk
               continue; 
           }
       }
       
       // NO MATCH: Write the original line exactly as is
       fprintf(memstream, "%s", line);
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


void sethostnameinxml(const char *hostname) {
  FILE *fp = fopen("config.xml", "r");
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
  /*char header[1024];
  if (fgets(header, sizeof(header), fp)) {
    fprintf(memstream, "%s", header); // Always keep header
  }*/

  // Process data lines, skipping the one to delete
  // auditions to maek it xml friendly
  char line[1024];
  //int found = 0;//no need
  char tag[] = "hostname";
  int updatedornot = 0;
  while (fgets(line, sizeof(line), fp)) {
    // Parse username from line (assuming format: username,password,level)
    // here tag
    //char username[256];
    char *start = strstr(line, "<hostname>");
    char *end = strstr(line, "</hostname>");
    char comparetag[64];
    if (start && end) {
        // Calculate indentation (whitespace before the tag)
        // This ensures the XML stays pretty-printed
        int indentation = (int)(start - line);//<-- ADDED by llm

        // Write the indentation, the opening tag, the NEW hostname, and the closing tag
        fprintf(memstream, "%.*s<hostname>%s</hostname>\n", indentation, line, hostname);
        updatedornot = 1;
  }
  else fprintf(memstream, "%s", line); // keep all other lines
}

  fclose(fp);
  fclose(memstream);

  //not necessary at all
  /*if (!found) {
    free(buffer);
    return;
  }*/

  // Rest of same...
  FILE *fptmp = fopen("config.tmp", "w");
  if (!fptmp) {
    perror("config.tmp");
    free(buffer);
    return;
  }

  if (fprintf(fptmp, "%s", buffer) < 0) {
    perror("Failed to write to temp file");
    fclose(fptmp);
    unlink("config.tmp");
    free(buffer);
    return;
  }

  fflush(fptmp);
  int fd = fileno(fptmp);
  fsync(fd);
  fclose(fptmp);

  if (rename("config.tmp", "config.xml") != 0) {
    perror("Failed to rename temp file");
    unlink("config.tmp");
    free(buffer);
    return;
  }

  free(buffer);
  if (updatedornot) {
      printf("{debug} updated to %s\n", hostname);
  } else {
      printf("Warning: <hostname> tag not found in config.xml\n");
  }
}


void setdnsinxml(const char *thattobeset, 
    const char *thetagtolookunderopen, const char *thetagtolookunderclose) {
  FILE *fp = fopen("config.xml", "r");
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
  
  char line[1024];
  while (fgets(line, sizeof(line), fp)) {
    char *start = strstr(line, thetagtolookunderopen/*"<hostname>"*/);
    char *end = strstr(line, thetagtolookunderclose/*"</hostname>"*/);
    if (start && end) {
        // Calculate indentation (whitespace before the tag)
        // This ensures the XML stays pretty-printed
        int indentation = (int)(start - line);//<-- ADDED by llm

        // Write the indentation, the opening tag, the NEW hostname, and the closing tag
        fprintf(memstream, "%.*s%s%s%s\n", indentation, line, thetagtolookunderopen/*start*/, thattobeset, thetagtolookunderclose/*end*/);
  }
  else fprintf(memstream, "%s", line); // keep all other lines
}

  fclose(fp);
  fclose(memstream);

  // Rest of same...
  FILE *fptmp = fopen("config.tmp", "w");
  if (!fptmp) {
    perror("config.tmp");
    free(buffer);
    return;
  }

  if (fprintf(fptmp, "%s", buffer) < 0) {
    perror("Failed to write to temp file");
    fclose(fptmp);
    unlink("config.tmp");
    free(buffer);
    return;
  }

  fflush(fptmp);
  int fd = fileno(fptmp);
  fsync(fd);
  fclose(fptmp);

  if (rename("config.tmp", "config.xml") != 0) {
    perror("Failed to rename temp file");
    unlink("config.tmp");
    free(buffer);
    return;
  }

  free(buffer);
}


void applydnstoservice(){
    FILE *fp = fopen("config.xml", "r");
    if(!fp) {perror("config in applytodns");
    return;}
    char line[1024];
    char searchdomain[256] = {0};
    char addr[64] = {0};
    char *s , *e;
    char *s1, *e1;
    while(fgets(line, sizeof(line), fp)){
        if((s = strstr(line , "<searchdomain>")) && (e = strstr(line , "</searchdomain>"))){
            int len = e - (s+14);
            if(len>0 && len < (int)sizeof(searchdomain) - 1){
                memcpy(searchdomain, s+14, len); // start + 14 of start
                                                // in short the value
                searchdomain[len] = '\0';
            }
        }
        if((s1 = strstr(line, "<addr>")) && (e1 = strstr(line, "</addr>"))){
              int len = e - (s + 6);
              if(len > 0 && len < (int)sizeof(addr) - 1){
                memcpy(addr, s + 6, len);
                addr[len] = '\0';
              }
            }
            
              if(!addr[0]){ 
                  printf("no dns address found in config.xml\n");
                 //fallback: if not found use the 1st auto like in multi net env
                 // use the addr[64]
                 char hostbuffer[256];
                 char *IPbuffer;
                 struct hostent *host_entry;
                 int hostname;
                 
                 // Retrieve hostname needed for gethostbyname so
                 hostname = gethostname(hostbuffer, sizeof(hostbuffer));
                 if (hostname == -1) {
                     perror("gethostname");
                     exit(1);
                    }
                 
                 // Retrieve host information by having hostname
                 host_entry = gethostbyname(hostbuffer);
                 if (host_entry == NULL) {
                     perror("gethostbyname");
                     exit(1);
                    }
                 
                // Convert the IP address to a string format
                // thats why ipbuffer, and have the base addr
                IPbuffer = inet_ntoa(*((struct in_addr*)host_entry->h_addr_list[0]));
                 
                // IP addr stored in IPbuffer, a char pointer
                char stored_ip[INET_ADDRSTRLEN]; // INET_ADDRSTRLEN is at least 16 for IPv4
                strncpy(stored_ip, IPbuffer, INET_ADDRSTRLEN - 1);
                stored_ip[INET_ADDRSTRLEN - 1] = '\0'; //null-termination
                FILE *tmpfallback = fopen("/etc/resolv.conf.tmp", "w");
                if(!tmpfallback){ perror("/etc/resolv.conf.tmp"); return; }
              
                fprintf(tmpfallback, "# generated by ONVIF-cameraserver SetDNS\n");
                if(searchdomain[0]) fprintf(tmpfallback, "search %s\n", searchdomain);
                fprintf(tmpfallback, "nameserver %s\n", stored_ip);
                fflush(tmpfallback);
                fsync(fileno(tmpfallback));
                fclose(tmpfallback);
              
                if(rename("/etc/resolv.conf.tmp", "/etc/resolv.conf") != 0){
                  perror("rename resolv.conf");
                  unlink("/etc/resolv.conf.tmp");
                  return;}
                return; }
            
              FILE *tmp = fopen("/etc/resolv.conf.tmp", "w");
              if(!tmp){ perror("/etc/resolv.conf.tmp"); return; }
            
              fprintf(tmp, "# generated by ONVIF-cameraserver SetDNS\n");
              if(searchdomain[0]) fprintf(tmp, "search %s\n", searchdomain);
              fprintf(tmp, "nameserver %s\n", addr);
              fflush(tmp);
              fsync(fileno(tmp));
              fclose(tmp);
            
              if(rename("/etc/resolv.conf.tmp", "/etc/resolv.conf") != 0){
                perror("rename resolv.conf");
                unlink("/etc/resolv.conf.tmp");
                return;
            }
    }
    
    fclose(fp);
}



#endif /*SET_DELETE_H */
