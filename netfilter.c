#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <sys/socket.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <libnet.h>

#define MAX 65548

static long my_ip;
static struct ifreq ifr;

unsigned char* replace_string(unsigned char input[], const char *old, const char *new , int ret)
{
	unsigned char *temp;
	int i_input=0;
	int old_len;
	
	old_len=strlen(old); 

	temp=(unsigned char*)malloc(ret);

	for(int j=0;j<ret;j++)
		temp[j]=input[j];

	while(i_input<ret)
	{
		if(memcmp(&temp[i_input], old, old_len)==0)
		{
			memcpy(&temp[i_input],new,old_len);
			i_input+=old_len;
		}
		else
			i_input++;
	}
	
	return temp;	
}

unsigned short tcp_checksum(const void *buff, int len, struct libnet_ipv4_hdr *iph)
{
	const unsigned short *tmp=buff;
	unsigned int sum;
	int length=len;
	unsigned short *src;
	unsigned short *dst;
	
	src=(unsigned short *) &(iph->ip_src.s_addr);
	dst=(unsigned short *) &(iph->ip_src.s_addr);
	
	sum=0;
	while( len>1)
	{
		sum+=*tmp++;
		if(sum & 0x80000000)
			sum=(sum & 0xffff) + (sum >>16);
		len-=2;
	}
		
	if( len & 1)
		sum+= *((unsigned char *)tmp);

	sum+=*(src++);
	sum+=*src;
	sum+=*(dst++);
	sum+=*dst;
	sum+=htons(IPPROTO_TCP);
	sum+=htons(length);

	while(sum>>16)
		sum= (sum & 0xffff)+ (sum>>16);

	return (unsigned short)(~sum);
}


int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data)
{
	unsigned int id=0;
	unsigned char *buffer;
	u_int32_t mark, ifi;
	int ret;
	struct nfqnl_msg_packet_hdr *ph;
	struct nfqnl_msg_packet_hw *hwph;
	struct libnet_ipv4_hdr *iph;
	struct libnet_tcp_hdr *tcph;
	int verdict;
	ph=nfq_get_msg_packet_hdr(nfa);

	if (ph){
		id=ntohl(ph->packet_id);
		printf("hw protocol = 0x%04x hook = %u id = %u\n ", ntohs(ph->hw_protocol), ph->hook, id);
	}	

	hwph=nfq_get_packet_hw(nfa);
	
	if (hwph){
		int i;
		int hlen=ntohs(hwph->hw_addrlen);
		printf("hlen: 0x%x\n",hlen);
		printf("hw src address = ");
		for (i=0;i<hlen-1;i++)
			printf("%02x:", hwph->hw_addr[i]);
		printf("%02x ", hwph->hw_addr[hlen-1]);
	}

	mark=nfq_get_nfmark(nfa);

	if(mark)
		printf("mark = %u\n",mark);

	ifi=nfq_get_indev(nfa);
	if(ifi)
		printf("indev = %u\n",ifi);

	ifi=nfq_get_outdev(nfa);
	if(ifi)
		printf("outdev = %u\n",ifi);

	ifi=nfq_get_physindev(nfa);
	if(ifi)
		printf("physindev = %u\n",ifi);

	if(ifi)
		printf("physoutdev = %u\n",ifi);

	ret=nfq_get_payload(nfa, &buffer);
	
	if(ret>=0)
		printf("payload len = %d\n", ret);

	iph=(struct libnet_ipv4_hdr*)buffer;
	tcph=(struct libnet_tcp_hdr*)(buffer+((iph->ip_hl)<<2));
	
	printf("ip source:%x \nip dest:%x\n",iph->ip_src.s_addr, iph->ip_dst.s_addr);

	if(ntohl(iph->ip_src.s_addr)==my_ip )
	{
		printf("let's change gzip\n");
		buffer=replace_string(buffer, "gzip","    " ,ret);
		tcph->th_sum=tcp_checksum(tcph,ret-((iph->ip_hl)<<2),iph);	
	
	}
	else if(ntohl(iph->ip_dst.s_addr)==my_ip && iph->ip_p==0x06)
	{
		printf("let's change michael\n");
		buffer=replace_string(buffer, "Michael", "gilbert" ,ret);
		tcph->th_sum=tcp_checksum(tcph,ret-((iph->ip_hl)<<2),iph);
	}

	printf("Entering callback\n");
   	printf("queue package %d \n", id);
	verdict= nfq_set_verdict(qh, id, NF_ACCEPT,ret, buffer);
	
	if(verdict)
		printf("verdict ok");
	return verdict;
}


int main(int argc, char **argv)
{
	int ip_fd,val;
	struct nfq_handle *h;
	struct nfq_q_handle *qh;
	int fd;
	int rv;
	int i=0;
	char *interface;
	char *errbuf;
	char buf[MAX] __attribute__ ((aligned));

	struct sockaddr_in *ipv4;

	interface=pcap_lookupdev(errbuf);
	printf("Interface : %s\n",interface);

	for(i=0;interface[i]!=0;i++)
	{
		ifr.ifr_ifrn.ifrn_name[i]=interface[i];
	}

	ifr.ifr_ifrn.ifrn_name[i]='\0';
	
	if((ip_fd=socket(AF_INET,SOCK_RAW,IPPROTO_RAW))<0)
	{
	  	perror ("socket() failed to get socket descriptor for using ioctl() ");
		return -1;
	}
	if((val=ioctl(ip_fd,SIOCGIFADDR,&ifr,sizeof(ifr)))<0)
	{
		perror("Fail to get my ip address");
		exit(1);
	}
	
	ipv4=(struct sockaddr_in *)&ifr.ifr_addr;
	my_ip=ntohl(ipv4->sin_addr.s_addr);

	printf("My IP address: %x \n", ipv4->sin_addr.s_addr);
	printf("Opening Library Handle\n");

	h=nfq_open();
	if(!h)
	{
		fprintf(stderr, "Error during nfq_open\n");
		exit(1);
	}

	printf("Unbinding existing nf_queue handler for AF_INET \n");
	if(nfq_unbind_pf(h, AF_INET)<0)
	{
		fprintf(stderr, "Error during nfq_unbind_pf()\n");
		exit(1);
	}

	printf("Binding nfnetlink_queue as nf_queue handler for AF_INET\n");
	

	if(nfq_bind_pf(h, AF_INET)<0)
	{
		fprintf(stderr, "Error during nfq_bind_pf()\n");
		exit(1);
	}

	printf("Binding this socket to queue '0'\n");
	qh=nfq_create_queue(h, 0, &cb, NULL);
	if(!qh)
	{
		fprintf(stderr, "Error during nfq_create_queue()\n");
		exit(1);
	}
	
	printf("Setting copy packet mode\n");
	fflush(stdout);
	if(nfq_set_mode(qh, NFQNL_COPY_PACKET,0xffff)<0)
	{
		fprintf(stderr, "Can't set packet copy mode\n");
		exit(1);
	}	

	fd=nfq_fd(h);

	while((rv=recv(fd,buf,sizeof(buf),0)) && rv>=0)
	{
	
		printf("Packet received, %d\n",rv);
		nfq_handle_packet(h,buf,rv);
		fflush(stdout);
	}
			

	printf("Unbinding from queue 0\n");
	nfq_destroy_queue(qh);

	printf("Close library handle\n");
	nfq_close(h);

	exit(0);

}
