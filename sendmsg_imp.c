#include <asm-generic/socket.h>
#include <bits/types/struct_iovec.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <linux/if_packet.h>
#include <asm/unistd.h>

#ifndef __NR_sendmmsg
#if defined( __PPC__)
#define __NR_sendmmsg 349
#elif defined(__x86_64__)
#define __NR_sendmmsg 307
#elif defined(__i386__)
#define __NR_sendmmsg 345
#else
#error __NR_sendmmsg not defined
#endif
#endif

struct mmsghdr {
    struct msghdr msg_hdr;
    unsigned int msg_len;
};

/*
    Wrapper for systemcall, wimplicit when not using this (sendmmsg only in glibc >2.14)
*/
static inline int sendmmsg(int fd, struct mmsghdr *mmsg, unsigned vlen, unsigned flags){
    return syscall(__NR_sendmmsg,fd,mmsg,vlen,flags,NULL);
}

/*
    Pseudoheader for csum calculation
*/
struct pseudo_header
{
	u_int32_t source_address;
	u_int32_t dest_address;
	u_int8_t placeholder;
	u_int8_t protocol;
	u_int16_t tcp_length;
};

/*
	Generic checksum calculation function
*/
unsigned short csum(unsigned short *ptr,int nbytes) 
{
	register long sum;
	unsigned short oddbyte;
	register short answer;

	sum=0;
	while(nbytes>1) {
		sum+=*ptr++;
		nbytes-=2;
	}
	if(nbytes==1) {
		oddbyte=0;
		*((u_char*)&oddbyte)=*(u_char*)ptr;
		sum+=oddbyte;
	}

	sum = (sum>>16)+(sum & 0xffff);
	sum = sum + (sum>>16);
	answer=(short)~sum;
	
	return(answer);
}

static int create_socket(char *interface){
	//Create a raw socket
	int s = socket (PF_INET, SOCK_RAW, IPPROTO_TCP);
	
	if(s == -1)
	{
		//socket creation failed, may be because of non-root privileges
		perror("Socket");
		exit(1);
	}

	const int len = strnlen(interface, IFNAMSIZ);
	if( len == IFNAMSIZ){
		//setting the interface failed
		fprintf(stderr, "Too long iface name!");
		exit(1); 
	}

	setsockopt(s, SOL_SOCKET, SO_BINDTODEVICE, interface, len);

	if( strcmp(interface, "")==0){
		printf("Interface set automatically\n");
	}else{
		printf("Interface set to: %s\n", interface);
	}
	
	return s;
}

void build_tcp(char *sHost, int sPort, char *dHost, int dPort, char *payload, struct msghdr *message, struct iovec * iov, char *datagram){
	//Datagram to represent the packet and zero out buffer
	char source_ip[32] , *data , *pseudogram; 
	memset(datagram, 0, 4096);

	//IP header
	struct iphdr *iph = (struct iphdr *) datagram;
	
	//TCP header
	struct tcphdr *tcph = (struct tcphdr *) (datagram + sizeof (struct ip));
	struct sockaddr_in sin;
	struct pseudo_header psh;
	
	//Data part
	data = datagram + sizeof(struct iphdr) + sizeof(struct tcphdr);
	strcpy(data , (char *) payload);
	
	//address resolution
	strcpy(source_ip , (char *) sHost);
	sin.sin_family = AF_INET;
	sin.sin_port = htons(80);
	sin.sin_addr.s_addr = inet_addr ((char *) dHost);
	
	//Fill in the IP Header
	iph->ihl = 5;
	iph->version = 4;
	iph->tos = 0;
	iph->tot_len = sizeof (struct iphdr) + sizeof (struct tcphdr) + strlen(data);
	iph->id = htonl (54321);	//Id of this packet
	iph->frag_off = 0;
	iph->ttl = 255;
	iph->protocol = IPPROTO_TCP;
	iph->check = 0;		//Set to 0 before calculating checksum
	iph->saddr = inet_addr ( source_ip );	//Spoof the source ip address
	iph->daddr = sin.sin_addr.s_addr;
	//Ip checksum
	iph->check = csum ((unsigned short *) datagram, iph->tot_len);
	
	//TCP Header
	tcph->source = htons (sPort);
	tcph->dest = htons (dPort);
	tcph->seq = 0;
	tcph->ack_seq = 0;
	tcph->doff = 5;	//tcp header size
	tcph->fin=0;
	tcph->syn=1;
	tcph->rst=0;
	tcph->psh=0;
	tcph->ack=0;
	tcph->urg=0;
	tcph->window = htons (5840);	/* maximum allowed window size */
	tcph->check = 0;	//leave checksum 0 now, filled later by pseudo header
	tcph->urg_ptr = 0;
	
	//Now the TCP checksum
	psh.source_address = inet_addr( source_ip );
	psh.dest_address = sin.sin_addr.s_addr;
	psh.placeholder = 0;
	psh.protocol = IPPROTO_TCP;
	psh.tcp_length = htons(sizeof(struct tcphdr) + strlen(data) );
	
	int psize = sizeof(struct pseudo_header) + sizeof(struct tcphdr) + strlen(data);
	pseudogram = malloc(psize);
	
	memcpy(pseudogram , (char*) &psh , sizeof (struct pseudo_header));
	memcpy(pseudogram + sizeof(struct pseudo_header) , tcph , sizeof(struct tcphdr) + strlen(data));
	
	tcph->check = csum( (unsigned short*) pseudogram , psize);
  
	iov->iov_base = datagram;	 //pointer to data
	iov->iov_len = iph->tot_len; //size of data

    int ret;
    struct addrinfo *ainfo;
    struct addrinfo hints = {
        .ai_family = PF_INET,
        .ai_socktype = SOCK_RAW,
        .ai_protocol = IPPROTO_TCP,
        .ai_flags = AI_PASSIVE,
    };

    //node, service, hints, result
    ret = getaddrinfo(dHost, NULL, &hints, &ainfo);
    message->msg_name = ainfo->ai_addr;          //optional address/socket name
    message->msg_namelen = ainfo->ai_addrlen;    //size of address
    message->msg_iov = iov;                      //iovec array
    message->msg_iovlen = 1;                     //elements in array

}

void do_tcp(int sock){	
	//IP_HDRINCL to tell the kernel that headers are included in the packet
	int one = 1;
	const int *val = &one;
	
	if (setsockopt (sock, IPPROTO_IP, IP_HDRINCL, val, sizeof (one)) < 0)
	{
		perror("Error setting IP_HDRINCL");
		exit(0);
	}

    struct mmsghdr messages[10];
    memset(messages, 0, sizeof(messages));

	struct msghdr hdr_probe = {};
	struct msghdr hdr_spoofed = {};
	char dgram_probe[4096] = "";
	char dgram_spoofed[4096] = "";
	struct iovec iov_probe = {};
	struct iovec iov_spoofed = {};

	char *dgram_ptr_probe = (char *) &dgram_probe;
	char *dgram_ptr_spoofed = (char *) &dgram_spoofed;
	struct iovec *iov_ptr_probe = &iov_probe;
	struct iovec *iov_ptr_spoofed = &iov_spoofed; 

	build_tcp("192.168.0.197", 10000, "1.2.3.4", 22222, "Probe", &hdr_probe, iov_ptr_probe ,dgram_ptr_probe);
	build_tcp("192.168.0.197", 10000, "1.2.3.4", 10010, "Spoofed", &hdr_spoofed, iov_ptr_spoofed, dgram_ptr_spoofed);;

	//probe and spoofed contain the same content at this point, but WHY?

	messages[0].msg_hdr = hdr_probe;
	messages[1].msg_hdr = hdr_spoofed;
	messages[2].msg_hdr = hdr_spoofed;
	messages[3].msg_hdr = hdr_spoofed;
	messages[4].msg_hdr = hdr_spoofed;
	messages[5].msg_hdr = hdr_spoofed;
	messages[6].msg_hdr = hdr_spoofed;
	messages[7].msg_hdr = hdr_spoofed;
	messages[8].msg_hdr = hdr_spoofed;
	messages[9].msg_hdr = hdr_probe;

    int retval;
	for(int i = 0; i<10; i++){
    	retval = sendmsg(sock, &hdr_probe, 0);
    	if (retval == -1){
        	perror("sendmsg()");
        	exit(1);
    	}
	}


}

int main(void){
    char *sHost;
	char *dHost;
    int sPort;
    int dPort;
    char *interface;
    int batch_size;

    sHost = "192.168.0.197";
    sPort = 10000;
    dHost = "1.2.3.4";
    dPort = 10010;
    batch_size = 10;
	interface = "lo"; //leave empty for autoset

	int sockfd = create_socket(interface);
	do_tcp(sockfd);

    return 0;
}
