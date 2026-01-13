#include <netinet/in.h>
#include <string.h>
#include <sys/socket.h>
#include <stdio.h>
#include <arpa/inet.h>

int main(void){
    /*
     * ok for looking into the header file socket.h
     * there are some extern functions and
     * apparently they lead to nowhere 
     * which makes me believe they are compiler constructs
     * or are in libc, confirmed are in libc
     * that is their workings exist but not explicitly
     * reacheable. they exist in kernel 
     * and are reachable using syscalls.
     * the list is below:(extern fn)
     * int socket();
     * int bind();
     * size_t bind();
     * size_t sendto();
     * size_t recvfrom();
     * etc. 
     * and the struct mmsghdr is used for other 
     * extern fns recvmsg & sendmsg both ssize_t
     * return types and the __THROW macro attached is for cpp
     */
     
     // to create a new socket 
     //int sockvar = socket(intdomain, inttype, intprotocol);
     // create 2 new sockets that are connected to each other and its 
     // directed to put file descriptors in FDS[0] and FDS[1]
     // which confirms my intuition about usage of pipe and fork
     //int socketpairvar = socketpair(intdomain, inttype, intprotocol, /*int*/ *fds);
     // takes socket fd the local address (len byte long addr)
     // what about this FD part of that forked array with 2 entries?
     //int bindvar = bind(int fd, const struct sockaddr *addr, socklen_t len);
     
     // initing file descriptor AF_INET = ipv4 protocol
     int sockfd = socket(AF_INET, SOCK_DGRAM, 0);// by 0
     // kernel chooses by default IPPROTO_UDP
     
         if (sockfd < 0) {
             perror("socket");
             return 1;
         }
     printf("socket fd = %d\n", sockfd);
         
     struct sockaddr_in addr;
     memset(&addr, 0/*init */, sizeof(addr));
     addr.sin_family = AF_INET;// expanded macro 2
     addr.sin_port = htons(9000);
     // htons converts unsigned short integer from host byte order
     // to network byte order and acronym for Host To Network Short 
     addr.sin_addr.s_addr =INADDR_ANY;
     // expansion of INADDR_ANY ((in_addr_t)0x00000000)
     bind(sockfd, (struct sockaddr *)&addr , sizeof(addr));
     // Incompatible pointer types passing 'struct sockaddr_in *' 
     // to parameter of type 'const struct sockaddr *' 
     // so type conversion still showing
     // The value returned by this function should not be disregarded; 
     // neglecting it may lead to errors (clang-tidy bugprone-unused-return-value)
     bind(fd, (struct sockaddr *)&addr, sizeof(addr)); no issues
     // at this line weird eventhough fd doesnt even exist!?
    
     // DO NOT COMPILE!!!! without making it comment
    
    
     char buf[64];// the "" will be stored here
     // recvfrom is a blocking i/o implementation
     // its working is specifically complex and hence comments in 
     // socket.h doesnt help that much, making it ambiguous
     recvfrom(fd, buf, sizeof(buf), 0, NULL, NULL);
     printf("%s", buf);
    
     close(fd);
    
     return 0;
}