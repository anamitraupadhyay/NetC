#ifndef DISCOVERY_SERVER_H
#define DISCOVERY_SERVER_H

#include <arpa/inet.h>
#include <asm-generic/socket.h>
#include <netinet/in.h>
#include <stdatomic.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <time.h>
#include <fcntl.h>

//#include "config.h"
//#include "simpleparser.h"
#include "dis_utils.h"

// from close observation there are 5 fields to be extracted
// 1. is it probe or discovery or not
// 2. uuid MEssageID from relatesTo
// 3. localip

// checking its probe or discovery 


// Disclaimer printf stmts are added by llm
void *discovery(void *arg) {
    (void)arg; // suppress unused warning
    printf("[DEBUG] process id:%d\n",getpid());

  printf("=== WS-Discovery Server ===\n");

  srand((unsigned)time(NULL));
  // init dev uuid
  initdevice_uuid();
  printf("[DEBUG] device endpoint uuid:%s\n",device_uuid);

  /*FILE *disxml = fopen("dis.xml", "r");
  if (disxml) {
    if (!is_xml_empty(disxml)) {
      fclose(disxml);
      load_preloaded_xml();
      return NULL;
    }
    fclose(disxml);
  }*/

  // Geting local IP
  char local_ip[64];
  getlocalip(local_ip, sizeof(local_ip));
  printf("Local IP: %s\n", local_ip);

  // Getting device name
  char device_name[64] = CAMERA_NAME;
  // getdevicename(device_name, 64);
  printf("device %s", device_name);
  
  char manufacturer[64] = {0};
  char hardware[64] = {0};
  char location[64] = {0};
  char profile[64] = {0};
  char type[64] = {0};

  // always on udp server
  // setupped with port
  int recieversocketudp = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  if (recieversocketudp < 0) {
    perror("socket");
    return NULL;
    }
    printf("socket created\n");
    // explicitly mentioned
    // about address reuse in header
    int opt =1;
    if(setsockopt(recieversocketudp,SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0){
        perror("setsockopt failed");
        // not fatal no need for return
    }

    //bind to address server side
    struct sockaddr_in recvside;

    memset(&recvside, 0, sizeof(recvside));
    recvside.sin_family = AF_INET;
    recvside.sin_port = htons(DISCOVERY_PORT);
    recvside.sin_addr.s_addr = INADDR_ANY;
    
    if (bind(recieversocketudp,
             (struct sockaddr*)&recvside,
             sizeof(recvside)) < 0) {
        perror("bind");
        return NULL;
    }
    
    printf("Bound to port %d\n", DISCOVERY_PORT);
    
    /* Join multicast group - THIS IS THE KEY PART */
    struct ip_mreq mreq;
    mreq.imr_multiaddr.s_addr = inet_addr(MULTICAST_ADDR);
    mreq.imr_interface.s_addr = INADDR_ANY;
    
    if (setsockopt(recieversocketudp, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) < 0) {
        perror("multicast join");
        close(recieversocketudp);
        return NULL;
    }
    printf("Joined multicast %s\n", MULTICAST_ADDR);
    
    printf("\nListening...  (Ctrl+C to stop)\n\n");

    // setting up buffers
    char recv_buf[BUFFER_SIZE];
    char send_buf[BUFFER_SIZE];

    // GET message id that is for relates to id
    char relates_to_id[256];

    char message_id[46];//urn:uuid(9)+36chars(uuid)+1\0
    
    //to represent client side and gonna iterate over
    struct sockaddr_in client_addr;
    socklen_t client_len;
    int probe_count = 0;

    while(1){
        client_len = sizeof(client_addr);
        memset(recv_buf, 0, sizeof(recv_buf));
        
        ssize_t n = recvfrom(recieversocketudp, recv_buf, sizeof(recv_buf) - 1, 0,
                             (struct sockaddr*)&client_addr, &client_len);
        
        if (n <= 0) continue;
        recv_buf[n] = '\0';
        
        // Check if it's a probe with error handling
        // will enhance the error handling later
        if (! isprobe(recv_buf)) {
            continue;
        }
        
        probe_count++;

        // this messageid from incoming probe next reponses' relatesto
        getmessageid(recv_buf, relates_to_id, sizeof(relates_to_id));

        // these 2 up and down function calls should
        // be inside here for each unique message parse

        // any random msgid for now later for resposnse
        generate_messageid(message_id, 46);
        //not here as i have a static var

        
        
        /* Get client IP for printing */
        char client_ip[64];
        inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, sizeof(client_ip));
        printf("[Probe #%d] from %s\n", probe_count, client_ip);

        
        // build response and send back
        int send_len =
            build_response(message_id, relates_to_id, message_id, manufacturer, hardware, location, profile, type, local_ip,
                           send_buf, sizeof(send_buf), device_name);
        FILE *xml = fopen("dis.xml", "w");
        fprintf(xml, "%s", send_buf);
        fclose(xml);

        // Send back 
        ssize_t sent = sendto(recieversocketudp, send_buf, (size_t)send_len, 0,
                              (struct sockaddr*)&client_addr, client_len);
        
        if (sent > 0) {
            printf("         Sent ProbeMatch (%zd bytes)\n", sent);
        }
    }
    return NULL;
}

#endif /* DISCOVERY_SERVER_H */
