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

static int create_raw_tcp_socket(char *ifname)
{
	int fd;
	struct ifreq ifr;

	fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
	if (fd < 0) {
		perror("socket");
		exit(1);
	}

	strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
	if (ioctl(fd, SIOCGIFINDEX, &ifr) < 0) {
		perror("ioctl");
		exit(1);
	}


	if (setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, (void *)&ifr, sizeof(ifr)) < 0) {
		perror("setsockopt");
		exit(1);
	}

	return fd;
}


struct pseudo_header
{
	u_int32_t source_address;
	u_int32_t dest_address;
	u_int8_t placeholder;
	u_int8_t protocol;
	u_int16_t tcp_length;
};

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

char* build_packet(char *src_ip, char *dst_ip, int src_port, int dst_port)
{
	struct iphdr *iph;
	struct tcphdr *tcph;
	struct sockaddr_in sin;
	struct pseudo_header psh;
	char *packet;
	int packet_size;

	//allocate the packet
	packet_size = sizeof(struct iphdr) + sizeof(struct tcphdr);
	packet = malloc(packet_size);

	//build the ip header
	iph = (struct iphdr *)packet;
	iph->ihl = 5;
	iph->version = 4;
	iph->tos = 0;
	iph->tot_len = htons(packet_size);
	iph->id = htons(54321);
	iph->frag_off = 0;
	iph->ttl = 255;
	iph->protocol = IPPROTO_TCP;
	iph->check = 0;
	iph->saddr = inet_addr(src_ip);
	iph->daddr = inet_addr(dst_ip);

	//build the tcp header
	tcph = (struct tcphdr *)(packet + sizeof(struct iphdr));
	tcph->source = htons(src_port);
	tcph->dest = htons(dst_port);
	tcph->seq = 0;
	tcph->ack_seq = 0;
	tcph->doff = 5;
	tcph->fin = 0;
	tcph->syn = 1;
	tcph->rst = 0;
	tcph->psh = 0;
	tcph->ack = 0;
	tcph->urg = 0;
	tcph->window = htons(5840);
	tcph->check = 0;
	tcph->urg_ptr = 0;

	//calculate the checksum
	psh.source_address = iph->saddr;
	psh.dest_address = iph->daddr;
	psh.placeholder = 0;
	psh.protocol = IPPROTO_TCP;
	psh.tcp_length = htons(sizeof(struct tcphdr));
	tcph->check = csum((unsigned short *)&psh, sizeof(struct pseudo_header));

	return packet;
}

void send_packets(char *ifname, char *src_ip, char *dst_ip, int src_port, int dst_port)
{
	int fd;
	char *packet;
	int i;

	fd = create_raw_tcp_socket(ifname);

	char packets[10][sizeof(struct iphdr) + sizeof(struct tcphdr)];
	for (i = 0; i < 10; i++) {
		packet = build_packet(src_ip, dst_ip, src_port, dst_port);
		memcpy(packets[i], packet, sizeof(struct iphdr) + sizeof(struct tcphdr));
	}

	struct sockaddr_in sin;
	sin.sin_family = AF_INET;
	sin.sin_port = htons(dst_port);
	sin.sin_addr.s_addr = inet_addr(dst_ip);


	int retval;
	for (i = 0; i < 10; i++) {
		retval = sendto(fd, packets[i], sizeof(struct iphdr) + sizeof(struct tcphdr), 0, (struct sockaddr *)&sin, sizeof(sin));
		if (retval<0) {
			perror("sendto");
			exit(1);
		}
	}
	close(fd);

	free(packet);
}

int main(int argc, char *argv[])
{
	send_packets("lo", "192.168.0.168", "1.2.3.4", 80, 22222);

	return 0;
}	