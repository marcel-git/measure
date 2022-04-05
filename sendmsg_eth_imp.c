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
#include <linux/if_ether.h>
#include <linux/if_arp.h>

//tcp pseudo header
struct pseudo_header
{
	u_int32_t source_address;
	u_int32_t dest_address;
	u_int8_t placeholder;
	u_int8_t protocol;
	u_int16_t tcp_length;
};

//ip checksum
unsigned short ip_checksum(unsigned short *ptr,int nbytes)
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

//tcp checksum that takes in the iphdr and tcphdr as well as the data as a string and data length
unsigned short tcp_checksum(struct iphdr *iph, struct tcphdr *tcph, char *data, int len)
{
	int i;
	struct pseudo_header psh;
	unsigned short buff[65536];
	memset(buff, 0, 65536);
	memcpy(buff, iph, sizeof(struct iphdr));
	memcpy(buff + sizeof(struct iphdr), tcph, sizeof(struct tcphdr));
	memcpy(buff + sizeof(struct iphdr) + sizeof(struct tcphdr), data, len);
	psh.source_address = iph->saddr;
	psh.dest_address = iph->daddr;
	psh.placeholder = 0;
	psh.protocol = IPPROTO_TCP;
	psh.tcp_length = htons(sizeof(struct tcphdr) + len);
	return ip_checksum((unsigned short *)&psh, sizeof(struct pseudo_header) + sizeof(struct tcphdr) + len);
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


//create a raw packet with ethernet header and ip header and tcp header and sends it to the network
int sendmsg_eth_imp(char *ifname, char *dst_mac, char *src_mac, char *dst_ip, char *src_ip, int dst_port, int src_port, char *data, int data_len)
{
	struct sockaddr_ll socket_address;
	struct ifreq ifr;
	struct ethhdr *eth_header;
	struct iphdr *ip_header;
	struct tcphdr *tcp_header;
	char *packet;
	int packet_len;
	int ret;

	//create a raw socket
	int sockfd = create_socket("lo");

	//allocate memory for the packet
	packet_len = sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr) + data_len;
	packet = (char *)malloc(packet_len);

	//fill the ethernet header
	eth_header = (struct ethhdr *)packet;
	eth_header->h_proto = htons(ETH_P_IP);
	eth_header->h_source[0] = src_mac[0];
	eth_header->h_source[1] = src_mac[1];
	eth_header->h_source[2] = src_mac[2];
	eth_header->h_source[3] = src_mac[3];
	eth_header->h_source[4] = src_mac[4];
	eth_header->h_source[5] = src_mac[5];
	eth_header->h_dest[0] = dst_mac[0];
	eth_header->h_dest[1] = dst_mac[1];	
	eth_header->h_dest[2] = dst_mac[2];
	eth_header->h_dest[3] = dst_mac[3];
	eth_header->h_dest[4] = dst_mac[4];
	eth_header->h_dest[5] = dst_mac[5];

	//fill the ip header
	ip_header = (struct iphdr *)(packet + sizeof(struct ethhdr));
	ip_header->ihl = 5;
	ip_header->version = 4;
	ip_header->tos = 0;
	ip_header->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr) + data_len);
	ip_header->id = htons(0);
	ip_header->frag_off = htons(0);
	ip_header->ttl = 64;
	ip_header->protocol = IPPROTO_TCP;
	ip_header->saddr = inet_addr(src_ip);
	ip_header->daddr = inet_addr(dst_ip);
	ip_header->check = 0;
	ip_header->check = ip_checksum((unsigned short *)ip_header, sizeof(struct iphdr));
	
	//fill the tcp header
	tcp_header = (struct tcphdr *)(packet + sizeof(struct ethhdr) + sizeof(struct iphdr));
	tcp_header->source = htons(src_port);
	tcp_header->dest = htons(dst_port);
	tcp_header->seq = htonl(0);
	tcp_header->ack_seq = htonl(0);
	tcp_header->doff = 5;
	tcp_header->fin = 0;
	tcp_header->syn = 1;
	tcp_header->rst = 0;
	tcp_header->psh = 0;
	tcp_header->ack = 0;
	tcp_header->urg = 0;
	tcp_header->window = htons(65535);
	tcp_header->check = 0;
	tcp_header->check = tcp_checksum(ip_header, tcp_header, data, data_len);

	//fill the data
	memcpy(packet + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr), data, data_len);

	struct msghdr hdr = {};
	struct iovec iov = {};

	iov.iov_base = packet;
	iov.iov_len = packet_len;

	struct addrinfo *ainfo;
	struct addrinfo hints = {
		.ai_family = AF_INET,
		.ai_socktype = SOCK_RAW,
		.ai_protocol = IPPROTO_RAW,
		.ai_flags = AI_PASSIVE
	};

	ret = getaddrinfo(dst_ip, NULL, &hints, &ainfo);
	
	hdr.msg_name = ainfo->ai_addr;
	hdr.msg_namelen = ainfo->ai_addrlen;
	hdr.msg_iov = &iov;
	hdr.msg_iovlen = 1;

	//10 times
	for(int i = 0; i < 10; i++){
		ret = sendmsg(sockfd, &hdr, 0);
		if(ret == -1){
			perror("sendmsg");
			exit(1);
		}
		printf("Packet sent!\n");
	}

	//free the packet
	free(packet);

	return 0;
}

//main function that takes no console arguments
int main(int argc, char *argv[])
{

	//Create a string to hold the data to send
	char *data = "Whatsup";
	int data_len = strlen(data);

	//send the packet
	if (sendmsg_eth_imp("lo", "0xDDD", "0xFFF", "1.2.3.4", "192.168.0.192", 22222, 80, data, data_len ) < 0)
	{
		return -1;
	}

	return 0;
}
