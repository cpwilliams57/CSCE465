
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <getopt.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/ether.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <linux/if_packet.h>

typedef unsigned char      byte;
typedef unsigned short int word;
typedef struct { byte *d; size_t l; } arr_t;            

//-----------------------------------------------------------
//Calculate the checksum of the provided buffer
//this function and much of this assignment utilized funcitons defined in 
// sniffing and spoofing module located at github.com/ispoleet/network security
//for reference and implementation aid
uint16_t chksum( byte buf[], size_t buflen )
{
    uint32_t sum = 0, i;                                
    if( buflen < 1 ) return 0;                         
    for( i=0; i<buflen-1; i+=2 ){
    	sum += *(word*)&buf[i];
    }
    if( buflen & 1 ){
    	sum += buf[buflen - 1];
    }           
    return ~((sum >> 16) + (sum & 0xffff));           
}

//-----------------------------------------------------------
//make the packet for the icmp ping
arr_t mk_ping_pkt( arr_t payload )
{
    arr_t pkt = {
        .d = malloc(sizeof(struct icmphdr) + payload.l),
        .l = sizeof(struct icmphdr) + payload.l
    };
    struct icmphdr *icmph = (struct icmphdr*) pkt.d;
    icmph->type     = ICMP_ECHO;                       
    icmph->code     = 0;
    icmph->checksum = 0;                                
    memcpy(&pkt.d[sizeof(struct icmphdr)], payload.d, payload.l);
    icmph->checksum = chksum(pkt.d, pkt.l);             
    return pkt;                                         
}

//-----------------------------------------------------------
//make an ip packet for the encapsulation of the ping packet
arr_t mk_ip_pkt( char *src, char *dst, byte proto, arr_t payload )
{
    arr_t pkt = {
        .d = malloc(sizeof(struct iphdr) + payload.l),
        .l = sizeof(struct iphdr) + payload.l
    };
    struct iphdr *iph = (struct iphdr*) pkt.d;
    
    //fill IP header
    iph->version  = 4;
    iph->ihl      = 5;
    iph->tos      = 0;
    iph->tot_len  = htons(pkt.l);                       
    iph->id       = htons(9999);                        
    iph->frag_off = 0;
    iph->ttl      = 64;
    iph->protocol = proto;                             
    iph->check    = 0;                                  
    iph->saddr    = inet_addr(src);                     
    iph->daddr    = inet_addr(dst);                     
    iph->check    = chksum(pkt.d, 20);                  
    
    //copy packet payload 
    memcpy(&pkt.d[sizeof(struct iphdr)], payload.d, payload.l);
    
    return pkt;                                         
}

//-----------------------------------------------------------
//creating raw soccket and sending packet
int snd_pkt(char *dst, arr_t pkt)
{

	//preprocessing for socket construction
    int    sd, on = 1;                                  
    struct sockaddr_in trg_addr = {                     
        .sin_zero        = { 0,0,0,0,0,0,0,0 },     
        .sin_family      = AF_INET,                
        .sin_port        = 0,                       
        .sin_addr.s_addr = inet_addr(dst)           
    };
    
    // create raw socket
    if((sd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0) {
        perror("Socket Creation error");
        return -1;
    }
    
    //add packet headers
    if( setsockopt(sd, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) < 0 ) {
        perror("IP error");
        return -1;
    }
    
    //send packet
    if(sendto(sd, pkt.d, pkt.l, 0, (struct sockaddr*)&trg_addr, sizeof(trg_addr)) < 0){
        perror("spood packet failed to send");
        return -1;
    }
    else
        printf( "Spoofed packet sent successfully!\n");
    
    return 0;                                          
}

//main function
int main( int argc, char *argv[] )
{
	//Initialize holders for atguements
    struct option longopt[] = {
        {"src-ip",  required_argument, 0, 'b'},
        {"dst-ip",  required_argument, 0, 'c'},
        {"payload", required_argument, 0, 'p'},
        {0,         0,                 0,  0 }
    };
    
    //initilize holders for source and destination ip and payload
    char  *srcip=NULL, *dstip=NULL, *payload=NULL;
    int   type, opt, longidx = 0;
    arr_t pkt = { .d = NULL, .l = 0 };
    
    //parse options provided at the command line
    while( (opt = getopt_long(argc, argv, "b:c:h", longopt, &longidx)) != -1)
        switch(opt)
    {
     
        case 'b': srcip  = optarg; break;
        case 'c': dstip  = optarg; break;
        case 'p': pkt.d  = optarg; pkt.l = strlen(optarg); break;
        return -1;             // failure
    }
    
    //send the ICMP packet
  	snd_pkt(dstip, mk_ip_pkt(srcip, dstip, IPPROTO_ICMP, mk_ping_pkt(pkt)));
    
    return 0;                                          
}
