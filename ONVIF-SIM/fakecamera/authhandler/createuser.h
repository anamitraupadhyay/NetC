//#include "getuser.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>

#include"digest_auth.h"
#include "set_delete.h"

#define MAX_USERS1 20
#define MAXFIELD_LEN 512

typedef struct {
    char username[MAXFIELD_LEN];
    char password[MAXFIELD_LEN];
    char userLevel[MAXFIELD_LEN];
} UserCreds;

// Standard ONVIF Fault Subcodes
#define FAULT_NOT_AUTHORIZED "ter:NotAuthorized"
#define FAULT_INVALID_ARG    "ter:InvalidArgVal"
#define FAULT_ACTION_NOT_SUP "ter:ActionNotSupported"


static int numofuserssent = 0;
// need to find better logic later for num of users sent
// the design needs to be clever as to parse efficiently
static UserCreds users[MAX_USERS1] = {0};

void parseSentUsers(const char *request);
void appendusers(const char *request, int accept);
int extract_tag(const char *source, const char *startTag,
    const char *endTag, char *destination);
void appendToCSV();


void parseSentUsers(const char *request){
    //const char *start = strstr(request,"<tds:CreateUsers>");
    //const char *end = strstr(request, "</tds:CreateUsers>");
    const char *movingCursor = request;// points to baseaddr

    // as per llm "request" is passed in while loop
    // due to which its starting from start
    // do movingCursor as its getting updated each loop
    while((movingCursor = strstr(/*request*/movingCursor, "<tds:User>")) != NULL){
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


void send_soap_fault(int client_sock, const char *subcode, const char *reason) {
    const char *fault_template =
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
        "<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\" "
        "xmlns:ter=\"http://www.onvif.org/ver10/error\">"
        "<s:Body>"
            "<s:Fault>"
                "<s:Code>"
                    "<s:Value>s:Sender</s:Value>"
                    "<s:Subcode><s:Value>%s</s:Value></s:Subcode>"
                "</s:Code>"
                "<s:Reason>"
                    "<s:Text xml:lang=\"en\">%s</s:Text>"
                "</s:Reason>"
            "</s:Fault>"
        "</s:Body>"
        "</s:Envelope>";

    char body[2048];
    snprintf(body, sizeof(body), fault_template, subcode, reason);

    char response[4096];
    snprintf(response, sizeof(response),
             "HTTP/1.1 500 Internal Server Error\r\n" // Faults are always 500
             "Content-Type: application/soap+xml; charset=utf-8\r\n"
             "Content-Length: %zu\r\n"
             "Connection: close\r\n\r\n%s",
             strlen(body), body);

    send(client_sock, response, strlen(response), 0);
}

void appendusers(const char *request,int accept) {
    // 1. Reset count necessary its a global var
    // and the improved design hasnt been applied yet
    numofuserssent = 0;

    // 2. Parse the XML
    parseSentUsers(request);

    char fail_reason[256];
    int validationpass = 1;

    printf("before loop validity check");
    for(int i = 0; i< numofuserssent; i++){
        printf("loop ran of validity check");
        if (!validate_cred_edgecases(users[i].username, users[i].password, fail_reason)){
            validationpass = 0; break;
            printf("validpass is now 0");
        }
    }
    printf("after loop validity check");

    if(validationpass == 1){
    // 3. Add the users to CredsWithLevel.csv
    appendToCSV();
    // taken template
                     // ONVIF Spec: CreateUsersResponse is empty on success
                     const char *soap_body =
                         "<?xml version=\"1.0\" encoding=\"utf-8\"?>"
                         "<soap:Envelope xmlns:soap=\"http://www.w3.org/2003/05/soap-envelope\" xmlns:tds=\"http://www.onvif.org/ver10/device/wsdl\">"
                             "<soap:Body>"
                                 "<tds:CreateUsersResponse></tds:CreateUsersResponse>"
                             "</soap:Body>"
                         "</soap:Envelope>";

                     char http_response[4096]; // Buffer size should be sufficient for this
                     int len = snprintf(http_response, sizeof(http_response),
                                 "HTTP/1.1 200 OK\r\n"
                                 "Content-Type: application/soap+xml; charset=utf-8\r\n"
                                 "Content-Length: %zu\r\n"
                                 "Connection: close\r\n"
                                 "\r\n"
                                 "%s",
                                 strlen(soap_body),
                                 soap_body);

                     // 4. Send the response
                     send(/*cs*/accept, http_response, len, 0);
    }
    else{
        send_soap_fault(accept, FAULT_INVALID_ARG, fail_reason);
    }
}

void setusers(const char *request,int accept) {
    // 1. Reset count necessary its a global var
    // and the improved design hasnt been applied yet
    numofuserssentupdate = 0;//its the necesssity as its used in parsesetusers

    // 2. Parse the XML
    parseSetUsers(request);

    char fail_reason[256];
    int validationpass = 1;

    // so the flow is 1st check the bounds
    // then if passed then only the check if this present or not in csv
    printf("before loop validity check");
    for(int i = 0; i< numofuserssentupdate; i++){
        printf("loop ran of validity check");
        if (!validate_cred_edgecases_forsetuser(users[i].username, users[i].password, fail_reason)){
            validationpass = 0; break;
            printf("validpass is now 0-bounds failed");
        }
        // ok after the bound has passed now check in db presence
        if(!user_exists_in_db(users[i].username)){
            // no need to set the validation pass for this case
            // i think doing the abrupt case check like validate fn 
            // as its standalone and snprintf-ing it 
            //validationpass = 1; 
            sprintf(/*reason_out*/ fail_reason, "user doesnt exist in db, cant update what isnt there");
            send_soap_fault(accept, FAULT_ACTION_NOT_SUP, fail_reason);
            printf("usernot in db");
            return;
        }
    }
    printf("after loop validity check");

    if(validationpass == 1){
    // 3. Add the users to CredsWithLevel.csv
    setuserscsv();
    // taken template
                     // ONVIF Spec: CreateUsersResponse is empty on success
                     const char *soap_body =
                         "<?xml version=\"1.0\" encoding=\"utf-8\"?>"
                         "<soap:Envelope xmlns:soap=\"http://www.w3.org/2003/05/soap-envelope\" xmlns:tds=\"http://www.onvif.org/ver10/device/wsdl\">"
                             "<soap:Body>"
                                 "<tds:SetUsersResponse></tds:SetUsersResponse>"
                             "</soap:Body>"
                         "</soap:Envelope>";

                     char http_response[4096]; // Buffer size should be sufficient for this
                     int len = snprintf(http_response, sizeof(http_response),
                                 "HTTP/1.1 200 OK\r\n"
                                 "Content-Type: application/soap+xml; charset=utf-8\r\n"
                                 "Content-Length: %zu\r\n"
                                 "Connection: close\r\n"
                                 "\r\n"
                                 "%s",
                                 strlen(soap_body),
                                 soap_body);

                     // 4. Send the response
                     send(/*cs*/accept, http_response, len, 0);
    }
    else{
        send_soap_fault(accept, FAULT_INVALID_ARG, fail_reason);
    }
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
