#include "library.h"
#include <sys/types.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/if_packet.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <errno.h>
#include <mhash.h>

/*Utility function*/
u_int16_t checksum (void * buffer, int bytes)
{
	 u_int32_t   total;
	 u_int16_t * ptr;
	 int        words;

	 total = 0;
	 ptr   = (uint16_t *) buffer;
	 words = (bytes + 1) / 2; // +1 & truncation on / handles any odd byte at end

	 /*
		*   As we're using a 32 bit int to calculate 16 bit checksum
		*   we can accumulate carries in top half of DWORD and fold them in later
		*/
	 while (words--) total += *ptr++;

	 /*
		*   Fold in any carries
		*   - the addition may cause another carry so we loop
		*/
	 while (total & 0xffff0000) total = (total >> 16) + (total & 0xffff);

	 return (u_int16_t) ~total;
}

void checksumTCP(ip_header *ip,tcp_header *tcp,void* data,size_t lenght)
{
	//Build pseudo-header TCP
	pseudo_header_tcp pseudo;
	pseudo.sourceAddress=ip->SourceAddress;
	pseudo.destAddress=ip->DestAddress;
	pseudo.zero=0;
	pseudo.proto=IPPROTO_TCP;
	pseudo.tcplenght=htons(HEADER_TCP+lenght);
	memset(&pseudo.zero,0,sizeof(char));
	//pseudo.tcp=tcp;
	int n=(sizeof(pseudo)+HEADER_TCP+lenght);
	void *info=(void*)malloc(n*sizeof(u_int16_t));
	memcpy(info,&pseudo,sizeof(pseudo));
	memcpy(info+sizeof(pseudo),tcp,HEADER_TCP);
	if(lenght!=0)
		memcpy(info+sizeof(pseudo)+HEADER_TCP,data,lenght);
	u_int16_t check=checksum(info,n);
	tcp->Checksum=check;
}

void checksumUDP(ip_header *ip,udp_header *tcp,void* data,size_t lenght)
{
	//Build pseudo-header TCP
	pseudo_header_tcp pseudo;
	pseudo.sourceAddress=ip->SourceAddress;
	pseudo.destAddress=ip->DestAddress;
	pseudo.zero=0;
	pseudo.proto=IPPROTO_UDP;
	pseudo.tcplenght=htons(HEADER_UDP+lenght);
	memset(&pseudo.zero,0,sizeof(char));
	//pseudo.tcp=tcp;
	int n=(sizeof(pseudo)+HEADER_UDP+lenght);
	void *info=(void*)malloc(n*sizeof(u_int16_t));
	memcpy(info,&pseudo,sizeof(pseudo));
	memcpy(info+sizeof(pseudo),tcp,HEADER_UDP);
	if(lenght!=0)
		memcpy(info+sizeof(pseudo)+HEADER_UDP,data,lenght);
	u_int16_t check=checksum(info,n);
	tcp->Checksum=check;
}

uint32_t checksumSCTP(uint8_t* buffer, int length)
{
	MHASH td;
	uint32_t checksum;
	td=mhash_init(MHASH_ADLER32);
	if(td==MHASH_FAILED)
		return 0;
	mhash(td,buffer,length);
	mhash_deinit(td,(void*)&checksum);
	return checksum;
}

void PrintHeaderIp(ip_header *ip)
{
	printf("\tVersion:\t%d\n",ip->Version);
	printf("\tInternet Header Lenght:\t%d\n",ip->IhL);
	printf("\tTOS:\n");
	printf("\t\tPrecedence:\t%d\n",ip->Prec);
	printf("\t\tLatency:\t%d\n",ip->Latenza);
	printf("\t\tThroughput:\t%d\n",ip->Thr);
	printf("\t\tAffidability:\t%d\n",ip->Affidability);
	printf("\t\tReserved:\t%d\n",ip->Reserved);
	printf("\tTotal Lenght:\t%d\n",ntohs(ip->Tot_Length));
	printf("\tFlags:\n");
	printf("\t\tReserved:\t%d\n",ip->Res);
	printf("\t\tDon't Fragment:\t%d\n",ip->DF);
	printf("\t\tMore Fragment:\t%d\n",ip->MF);
	printf("\tFragment Offset:\t%d\n",ip->Offset);
	printf("\tTime to Live:\t%d\n",ip->TTL);
	switch(ip->Protocol)
	{
		case IPPROTO_TCP:
			printf("\tProtocol:\tTCP(%d)\n",ip->Protocol);
		break;
		case IPPROTO_UDP:
			printf("\tProtocol:\tUDP(%d)\n",ip->Protocol);
		break;
		case IPPROTO_SCTP:
			printf("\tProtocol:\tSCTP(%d)\n",ip->Protocol);
		break;
		case IPPROTO_ICMP:
			printf("\tProtocol:\tICMP(%d)\n",ip->Protocol);
		break;
		default:
			printf("\tProtocol:\t%d\n",ip->Protocol);
		break;
	}
	printf("\tHeader Checksum:0x%02X\n",ip->HeaderChecksum);
	unsigned char bytes[4];
	bytes[0]=ip->SourceAddress & 0xFF;
	bytes[1]=(ip->SourceAddress >> 8) & 0xFF;
	bytes[2]=(ip->SourceAddress >> 16) & 0xFF;
	bytes[3]=(ip->SourceAddress >> 24) & 0xFF;
	printf("\tSource Address:%d.%d.%d.%d\n",bytes[0],bytes[1],bytes[2],bytes[3]);
	bytes[0]=ip->DestAddress & 0xFF;
	bytes[1]=(ip->DestAddress >> 8) & 0xFF;
	bytes[2]=(ip->DestAddress >> 16) & 0xFF;
	bytes[3]=(ip->DestAddress >> 24) & 0xFF;
	printf("\tDestination Address:%d.%d.%d.%d\n",bytes[0],bytes[1],bytes[2],bytes[3]);
}

void PrintHeaderTCP(tcp_header *tcp)
{
	printf("\tSource Port:\t%d\n",ntohs(tcp->sourcePort));
	printf("\tDestination Port:\t%d\n",ntohs(tcp->destPort));
	printf("\tSequence Number:\t%d\n",ntohs(tcp->sequence));
	printf("\tAcknowledgment Number:\t%d\n",ntohs(tcp->Ack));
	printf("\tData Offset:\t%d\n",tcp->DataOffset);
	printf("\tReserved:\t%d\n",ntohs(tcp->Reserved));
	printf("\tFlags:\n");
	printf("\t\tCWR:\t%d\n",tcp->CWR);
	printf("\t\tECE:\t%d\n",tcp->ECE);
	printf("\t\tURG:\t%d\n",tcp->URG);
	printf("\t\tACK:\t%d\n",tcp->ACK);
	printf("\t\tPSH:\t%d\n",tcp->PSH);
	printf("\t\tRST:\t%d\n",tcp->RST);
	printf("\t\tSYN:\t%d\n",tcp->SYN);
	printf("\t\tFIN:\t%d\n",tcp->FIN);
	printf("\tWindows Size:\t%d\n",ntohs(tcp->WindowSize));
	printf("\tUrgent Pointer:\t%d\n",ntohs(tcp->UrgentPointer));
	printf("\tChecksum:\t0x%02X\n",ntohl(tcp->Checksum));
}

void PrintHeaderUDP(udp_header *udp)
{
	printf("\tSource Port:\t%d\n",ntohs(udp->sourcePort));
	printf("\tDestination Port:\t%d\n",ntohs(udp->destPort));
	printf("\tLength:\t%d\n",ntohs(udp->lenght));
	printf("\tChecksum:\t0x%02X\n",ntohl(udp->Checksum));
}

void PrintHeaderSCTP(sctp_header *sctp)
{
	printf("\tSource Port:\t%d\n",ntohs(sctp->sourcePort));
	printf("\tDestination Port:\t%d\n",ntohs(sctp->destPort));
	printf("\tVerification Tag Number:\t%d\n",ntohl(sctp->verTag));
	printf("\tChecksum:\t0x%04X\n",ntohl(sctp->Checksum));
}

void PrintHeaderICMP(icmp_header *icmp)
{	
	switch(icmp->Type)
	{
		case 0:
			printf("\tType:\tEcho Reply(%d)\n",icmp->Type);
			printf("\tCode:\t%d\n",icmp->Code);
			break;
		case 3:
			printf("\tType:\tDestination Unreachable(%d)\n",icmp->Type);
			switch(icmp->Code)
			{
				case 0:
					printf("\tCode:\tDestination Network Unreachable(%d)\n",icmp->Code);
					break;
				case 1:
					printf("\tCode:\tDestination Host Unreachable(%d)\n",icmp->Code);
					break;
				case 2:
					printf("\tCode:\tDestination Protocol Unreachable(%d)\n",icmp->Code);
					break;
				case 3:
					printf("\tCode:\tDestination Port Unreachable(%d)\n",icmp->Code);
					break;
				case 4:
					printf("\tCode:\tFragmentation Required and DF flag set(%d)\n",icmp->Code);
					break;
				case 5:
					printf("\tCode:\tSource Route Failed(%d)\n",icmp->Code);
					break;
				case 6:
					printf("\tCode:\tDestination Network Unknown(%d)\n",icmp->Code);
					break;
				case 7:
					printf("\tCode:\tDestination Host Unknown(%d)\n",icmp->Code);
					break;
				case 8:
					printf("\tCode:\tSource Host Isolated(%d)\n",icmp->Code);
					break;
				case 9:
					printf("\tCode:\tNetwork Administratively Prohibited(%d)\n",icmp->Code);
					break;
				case 10:
					printf("\tCode:\tHost Administratively Prohibited(%d)\n",icmp->Code);
					break;
				case 11:
					printf("\tCode:\tNetwork Unreachable for TOS(%d)\n",icmp->Code);
					break;
				case 12:
					printf("\tCode:\tHost Unreachable for TOS(%d)\n",icmp->Code);
					break;
				case 13:
					printf("\tCode:\tCommunication Administratively Prohibited(%d)\n",icmp->Code);
					break;
				case 14:
					printf("\tCode:\tHost Precedence Violation(%d)\n",icmp->Code);
					break;
				case 15:
					printf("\tCode:\tPrecedence Cutoff in Effect(%d)\n",icmp->Code);
					break;
				default:
					printf("\tCode:\t%d\n",icmp->Code);
					break;
			}
			break;
		case 4:
			printf("\tType:\tSource Quence(%d)\n",icmp->Type);
			printf("\tCode:\t%d\n",icmp->Code);
			break;
		case 5:
			printf("\tType:\tRedirect(%d)\n",icmp->Type);
			switch(icmp->Code)
			{
				case 0:
					printf("\tCode:\tRedirect Datagram for the Network(%d)\n",icmp->Code);
					break;
				case 1:
					printf("\tCode:\tRedirect Datagram for the Host(%d)\n",icmp->Code);
					break;
				case 2:
					printf("\tCode:\tRedirect Datagram for the TOS and Network(%d)\n",icmp->Code);
					break;
				case 3:
					printf("\tCode:\tRedirect Datagram for the TOS and Host(%d)\n",icmp->Code);
					break;
				default:
					printf("\tCode:\t%d\n",icmp->Code);
					break;
			}
			break;
		case 6:
			printf("\tType:\tAlternative Host Address(%d)\n",icmp->Type);
			printf("\tCode:\t%d\n",icmp->Code);
			break;
		case 8:
			printf("\tType:\tEcho Request(%d)\n",icmp->Type);
			printf("\tCode:\t%d\n",icmp->Code);
			break;
		case 9:
			printf("\tType:\tRouter Advertisement(%d)\n",icmp->Type);
			printf("\tCode:\t%d\n",icmp->Code);
			break;
		case 10:
			printf("\tType:\tRouter Solicitation(%d)\n",icmp->Type);
			printf("\tCode:\t%d\n",icmp->Code);
			break;
		case 11:
			printf("\tType:\tTime Exceeded(%d)\n",icmp->Type);
			switch(icmp->Code)
			{
				case 0:
					printf("\tCode:\tTTL Expired in Transit(%d)\n",icmp->Code);
					break;
				case 1:
					printf("\tCode:\tFragment Reassembly Time Exceeded(%d)\n",icmp->Code);
					break;
				default:
					printf("\tCode:\t%d\n",icmp->Code);
					break;
			}
			break;
		case 12:
			printf("\tType:\tParameter Problem: Bad IP Header(%d)\n",icmp->Type);
			switch(icmp->Code)
			{
				case 0:
					printf("\tCode:\tPointer Indicates the Error(%d)\n",icmp->Code);
					break;
				case 1:
					printf("\tCode:\tMissing a Required Option(%d)\n",icmp->Code);
					break;
				case 2:
					printf("\tCode:\tBad Length(%d)\n",icmp->Code);
					break;
				default:
					printf("\tCode:\t%d\n",icmp->Code);
					break;
			}
			break;
		case 13:
			printf("\tType:\tTimestamp(%d)\n",icmp->Type);
			printf("\tCode:\t%d\n",icmp->Code);
			break;
		case 14:
			printf("\tType:\tTimestamp Reply(%d)\n",icmp->Type);
			printf("\tCode:\t%d\n",icmp->Code);
			break;
		case 15:
			printf("\tType:\tInformation Request(%d)\n",icmp->Type);
			printf("\tCode:\t%d\n",icmp->Code);
			break;
		case 16:
			printf("\tType:\tInformation Reply(%d)\n",icmp->Type);
			printf("\tCode:\t%d\n",icmp->Code);
			break;
		case 17:
			printf("\tType:\tAddress Mask Request(%d)\n",icmp->Type);
			printf("\tCode:\t%d\n",icmp->Code);
			break;
		case 18:
			printf("\tType:\tAddress Mask Reply(%d)\n",icmp->Type);
			printf("\tCode:\t%d\n",icmp->Code);
			break;
		case 30:
			printf("\tType:\tTraceroute(%d)\n",icmp->Type);
			printf("\tCode:\t%d\n",icmp->Code);
			break;
		default:
			printf("\tType:\t%d\n",icmp->Type);
			printf("\tCode:\t%d\n",icmp->Code);
			break;
	}
	printf("\tChecksum:\t0x%02X\n",ntohs(icmp->Checksum));
	printf("\tRest:\t0x%04X\n",ntohl(icmp->Rest));
}

void PrintHeaderEth(eth_header_tx *head)
{
	printf("\tDestination address:\t");
	int k;
	for(k=0;k<5;k++)
		printf("%02X:",head->destination[k]);
	printf("%02X\n",head->destination[5]);
	printf("\tSource address:\t");
	for(k=0;k<5;k++)
		printf("%02X:",head->source[k]);
	printf("%02X\n",head->source[5]);
	printf("\tLength:\t%d\n",head->length);
}

void PrintArp(arp_hdr *rq)
{
	if(rq->htype==1)
		printf("\tHardware type:\tEthernet(%d)\n",rq->htype);
	else
		printf("\tHardware type:\t%d\n",rq->htype);
	if(rq->ptype==0x0800)
		printf("\tProtocol Type:\tIP(%d)\n",rq->ptype);
	else
		printf("\tProtocol Type:\t%d\n",rq->ptype);
	printf("\tHardware Length:\t%d\n",rq->hlen);
	printf("\tProtocol Length:\t%d\n",rq->plen);
	int op=ntohs(rq->opcode);
	if(op == 1)
		printf("Operation:\tRequest(%d)\n",op);
	else if(op == 2)
		printf("Operation:\tReply(%d)\n",op);
	else if(op== 3)
		printf("Operation:\tReverse ARP(%d)\n",op);
	else
		printf("Operation:\t%d\n",rq->opcode);
	printf("\tMac Sender:\t%02X:%02X:%02X:%02X:%02X:%02X\n",rq->sender_mac[0],rq->sender_mac[1],rq->sender_mac[2],rq->sender_mac[3],rq->sender_mac[4],rq->sender_mac[5]);
	printf("\tIP Sender:\t%d.%d.%d.%d\n",rq->sender_ip[0],rq->sender_ip[1],rq->sender_ip[2],rq->sender_ip[3]);
	printf("\tMac Target:\t%02X:%02X:%02X:%02X:%02X:%02X\n",rq->target_mac[0],rq->target_mac[1],rq->target_mac[2],rq->target_mac[3],rq->target_mac[4],rq->target_mac[5]);
	printf("\tIP Target:\t%d.%d.%d.%d\n",rq->target_ip[0],rq->target_ip[1],rq->target_ip[2],rq->target_ip[3]);
}

void PrintPacket(uint8_t *packet, size_t length)
{
	int k;
	for(k=0;k<length;k++)
		if(k%5 == 0)
		{
			printf("\n0x%04d\t",k);
			printf("0x%02X\t",(unsigned int)packet[k]);
		}
		else
			printf("0x%02X\t",(unsigned int)packet[k]);
	printf("\n");
}


void list_interface(int fd) {
	struct ifreq *ifreq;
	struct ifconf ifconf;
	char buf[16384];
	unsigned i;
	size_t len;

	ifconf.ifc_len=sizeof buf;
	ifconf.ifc_buf=buf;
	if(ioctl(fd, SIOCGIFCONF, &ifconf)!=0) {
		perror("Error");
	}
	else {
		ifreq=ifconf.ifc_req;
		for(i=0;i<ifconf.ifc_len;) {
			/* some systems have ifr_addr.sa_len and adjust the length that
			 * way, but not mine. weird */
	#ifndef linux
			len=IFNAMSIZ + ifreq->ifr_addr.sa_len;
	#else
			len=sizeof *ifreq;
	#endif
			struct ifreq req;
			memset(&req,0,sizeof(req));
			strcpy(req.ifr_name,ifreq->ifr_name);
			if(ioctl(fd,SIOCGIFINDEX,&req)<0)
			{
				perror("Error");
			}
			else
			{
				printf("\t%d)%s\n",req.ifr_ifindex,req.ifr_name);
				ifreq=(struct ifreq*)((char*)ifreq+len);
				i+=len;
			}
		}
	}
}

/*3 Level of stack*/

int FuzzyIP(char* iface,ip_header ip,int raw,void *head_protocol,void* data,size_t lenght)
{
	uint8_t *buffer;
	uint8_t *packet;
	size_t sending=0;
	if(raw!=1)
	{
		if(ip.Protocol==IPPROTO_TCP)
		{
			buffer=(uint8_t*)malloc((HEADER_ETH+HEADER_IP+HEADER_TCP+lenght)*sizeof(uint8_t));
			if(buffer==NULL)
			{
				perror("Error: Maybe memory error");
				return errno;
			}
			packet=buffer+HEADER_ETH;
			tcp_header *testa_tcp=(tcp_header*)head_protocol;
			checksumTCP(&ip,testa_tcp,data,lenght);
			ip.HeaderChecksum=0;
			ip.HeaderChecksum=checksum((void*)&ip,HEADER_IP);
			memcpy(packet,&ip,HEADER_IP * sizeof (uint8_t));
			memcpy(packet+HEADER_IP,testa_tcp,HEADER_TCP*sizeof(uint8_t));
			if(lenght!=0)
				memcpy(packet+HEADER_IP+HEADER_TCP,data,lenght*sizeof(uint8_t));
			sending=HEADER_IP+HEADER_TCP+lenght;
		}
		else if(ip.Protocol == IPPROTO_UDP)
		{
			buffer=(uint8_t*)malloc((HEADER_ETH+HEADER_IP+HEADER_UDP+lenght)*sizeof(uint8_t));
			if(buffer==NULL)
			{
				perror("Error: Maybe memory error");
				return errno;
			}
			packet=buffer+HEADER_ETH;
			udp_header *testa_udp=(udp_header*)head_protocol;
			checksumUDP(&ip,testa_udp,data,lenght);
			ip.HeaderChecksum=0;
			ip.HeaderChecksum=checksum((void*)&ip,HEADER_IP);
			memcpy(packet,&ip,HEADER_IP * sizeof (uint8_t));
			memcpy(packet+HEADER_IP,testa_udp,HEADER_UDP*sizeof(uint8_t));
			if(lenght!=0)
				memcpy(packet+HEADER_IP+HEADER_UDP,data,lenght*sizeof(uint8_t));
			sending=HEADER_IP+HEADER_UDP+lenght;
		}
		else if(ip.Protocol==IPPROTO_SCTP)
		{
			buffer=(uint8_t*)malloc((HEADER_ETH+HEADER_IP+HEADER_SCTP+lenght)*sizeof(uint8_t));
			if(buffer==NULL)
			{
				perror("Error: Maybe memory error");
				return errno;
			}
			sctp_header *testa_sctp=(sctp_header*)head_protocol;
			packet=buffer+HEADER_ETH;

			uint8_t* check=(uint8_t*) malloc(HEADER_SCTP+lenght*sizeof(uint8_t));
			if(buffer==NULL)
			{
				perror("Error: Maybe memory error");
				return errno;
			}
			testa_sctp->Checksum=0;
			memcpy(check,testa_sctp,HEADER_SCTP*sizeof(uint8_t));
			memcpy(check+HEADER_SCTP,data,lenght);
			testa_sctp->Checksum=htonl(checksumSCTP(check,HEADER_SCTP+lenght));
			free(check);
			ip.HeaderChecksum=0;
			ip.HeaderChecksum=checksum((void*)&ip,HEADER_IP);
			memcpy(packet,&ip,HEADER_IP*sizeof(uint8_t));
			memcpy(packet+HEADER_IP,testa_sctp,HEADER_SCTP*sizeof(uint8_t));
			if(lenght!=0)
				memcpy(packet+HEADER_IP+HEADER_SCTP,data,lenght*sizeof(uint8_t));
			sending=HEADER_IP+HEADER_SCTP+lenght;
		}
		else if(ip.Protocol==IPPROTO_ICMP)
		{
			buffer=(uint8_t*)malloc((HEADER_ETH+HEADER_IP+HEADER_ICMP+lenght)*sizeof(uint8_t));
			if(buffer==NULL)
			{
				perror("Error: Maybe memory error");
				return errno;
			}
			packet=buffer+HEADER_ETH;
			icmp_header* testa_icmp=(icmp_header*)head_protocol;
			ip.HeaderChecksum=0;
			ip.HeaderChecksum=checksum((void*)&ip,HEADER_IP);
			memcpy(packet,&ip,HEADER_IP*sizeof(uint8_t));
			if(lenght != 0)
			{
				/*Calculate the ckecsum of ICMP*/
				uint8_t* pkg=(uint8_t*)malloc((lenght+HEADER_ICMP)*sizeof(uint8_t));
				if(buffer==NULL)
				{
					perror("Error: Maybe memory error");
					return errno;
				}
				memcpy(pkg,testa_icmp,HEADER_ICMP);
				memcpy(pkg+HEADER_ICMP,data,lenght*sizeof(uint8_t));
				testa_icmp->Checksum=checksum((void*)pkg,(HEADER_ICMP+lenght));
				free(pkg);
				memcpy(packet+HEADER_IP,testa_icmp,HEADER_ICMP*sizeof(uint8_t));
				memcpy(packet+HEADER_IP+HEADER_ICMP,data,lenght*sizeof(uint8_t));
			}
			else
			{
				uint8_t* pkg=(uint8_t*)malloc((HEADER_IP+HEADER_ICMP)*sizeof(uint8_t));
				if(buffer==NULL)
				{
					perror("Error: Maybe memory error");
					return errno;
				}
				memcpy(pkg,testa_icmp,HEADER_ICMP*sizeof(uint8_t));
				testa_icmp->Checksum=checksum((void*)pkg,HEADER_ICMP);
				free(pkg);
				memcpy(packet+HEADER_IP,testa_icmp,HEADER_ICMP*sizeof(uint8_t));
			}
			sending=HEADER_IP+HEADER_ICMP+lenght;
		}
		else
		{
			buffer=(uint8_t*)malloc((HEADER_IP)*sizeof(uint8_t));
			if(buffer==NULL)
			{
				perror("Error: Maybe memory error");
				return errno;
			}
			packet=buffer+HEADER_ETH;
			memcpy(packet,&ip,HEADER_IP * sizeof (uint8_t));
			sending=HEADER_IP;
		}
	}
	else
	{
		buffer=(uint8_t*)malloc((HEADER_ETH+HEADER_IP+lenght)*sizeof(uint8_t));
		if(buffer==NULL)
		{
			perror("Error: Maybe memory error");
			return errno;
		}
		packet=buffer+HEADER_ETH;
		ip.HeaderChecksum=0;
		ip.HeaderChecksum=checksum((void*)&ip,HEADER_IP);
		memcpy(packet,&ip,HEADER_IP * sizeof (uint8_t));
		if(lenght>0)
			memcpy(packet+HEADER_IP,data,lenght*sizeof(uint8_t));
		sending=HEADER_IP+lenght;
	}
	sending=sending+HEADER_ETH;
	int er=FuzzyEth_IP(buffer,sending,iface,ip.DestAddress);
	if(er<0)
	{
		perror("Error");
		return errno;
	}
	free(buffer);
	return 0;
}


int FuzzyEth_IP(uint8_t *buffer,size_t length,char *iface,uint32_t ipaddress)
{
	eth_header_tx eth;
	eth.length=htons(0x0800);
	struct hwinfo address;
	address.destIp=ipaddress;
	if(resolution(iface,&address)<0)
	{
		perror("Error");
		return -1;
	}
	memcpy(&eth.destination,&address.receive_mac,6);
	memcpy(&eth.source,&address.sender_mac,6);
	/*HEADER ETH FORGED*/
	memcpy(buffer,&eth,HEADER_ETH);
	return PSend(buffer,length,eth.destination,iface);
}

int resolution(char* iface,struct hwinfo* dest)
{
	//Creazione socket
	int fd=-1;
	arp_hdr arpr;
	const unsigned char broad[]={0xff,0xff,0xff,0xff,0xff,0xff};
	int inetsock=socket(AF_INET,SOCK_DGRAM,0);
	if(inetsock<0)
	{
		perror("Error");
		close(inetsock);
		return -1;
	}
	//Acquisizione dati sorgenti
	struct ifreq ifr2;
	memset(&ifr2,0,sizeof(ifr2));
  	snprintf(ifr2.ifr_name,sizeof(ifr2.ifr_name),"%s",iface);
  	ifr2.ifr_addr.sa_family=AF_INET;
	//Richiesta IP sorgente
  	if(ioctl(inetsock,SIOCGIFADDR,&ifr2)<0)
  	{
  		perror ("Error: Maybe failed to find IP");
  		close(inetsock);
    	return -1;	
  	}
  	struct sockaddr_in *str=(struct sockaddr_in*)&ifr2.ifr_addr;
  	struct in_addr *lp=(struct in_addr*)&str->sin_addr;
  	arpr.sender_ip[0]=lp->s_addr & 0xFF;
	arpr.sender_ip[1]=(lp->s_addr >> 8) & 0xFF;
	arpr.sender_ip[2]=(lp->s_addr >> 16) & 0xFF;
	arpr.sender_ip[3]=(lp->s_addr >> 24) & 0xFF;
  	//Richiesta MAC sorgente
  	if(ioctl(inetsock,SIOCGIFHWADDR,&ifr2)<0)
  	{
  		perror("Error: Maybe failed to find MAC");
  		close(inetsock);
  		return -1;
  	}
  	memcpy(&dest->sender_mac,&ifr2.ifr_hwaddr.sa_data[0],ETH_ADDR_LEN);
	//printf("Sorgente MAC:\n");
	//printf("\t-> %02X:%02X:%02X:%02X:%02X:%02X\n",dest->sender_mac[0],dest->sender_mac[1],dest->sender_mac[2],dest->sender_mac[3],dest->sender_mac[4],dest->sender_mac[5]);

	/*Interface number */
	struct ifreq ifr;
	memset (&ifr, 0, sizeof (ifr));
  	snprintf (ifr.ifr_name, sizeof (ifr.ifr_name), "%s", iface);
  	if (ioctl (inetsock, SIOCGIFINDEX, &ifr) < 0) {
    	perror ("Error: Maybe failed to find interface");
    	close(inetsock);
    	return -1;
    }
    int idface=ifr.ifr_ifindex;

	/*Dati per la richiesta ARP*/
	struct sockaddr_ll addr={0};
	addr.sll_family=AF_PACKET;
	addr.sll_ifindex=idface;
	addr.sll_halen=ETH_ADDR_LEN;
	addr.sll_protocol=htons(ETH_P_ARP);
	memcpy(addr.sll_addr,broad,ETHER_ADDR_LEN);
	arpr.htype=htons(0x01);
	arpr.ptype=htons(ETH_P_IP);
	arpr.hlen=ETHER_ADDR_LEN;
	arpr.plen=4;
	arpr.opcode=htons(ARPOP_REQUEST);
	memcpy(arpr.sender_mac,dest->sender_mac,arpr.hlen);
	memset(arpr.target_mac,0,arpr.hlen);
	arpr.target_ip[0]=dest->destIp & 0xFF;
	arpr.target_ip[1]=(dest->destIp >> 8) & 0xFF;
	arpr.target_ip[2]=(dest->destIp >> 16) & 0xFF;
	arpr.target_ip[3]=(dest->destIp >> 24) & 0xFF;
	//printf("Sorgente IP:%d.%d.%d.%d\n",arpr.sender_ip[0],arpr.sender_ip[1],arpr.sender_ip[2],arpr.sender_ip[3]);
	//printf("Destinazione IP:%d.%d.%d.%d\n",arpr.target_ip[0],arpr.target_ip[1],arpr.target_ip[2],arpr.target_ip[3]);
	uint8_t buffer[sizeof(arp_hdr)];
	memcpy(buffer,&arpr,32);

	//Richiesta ARP cache
	struct sockaddr_in *sin;
	struct arpreq arp;
	memset(&arp,0,sizeof(arp));
	sin=(struct sockaddr_in*) &arp.arp_pa;
	sin->sin_family=AF_INET;
	sin->sin_addr.s_addr=dest->destIp;
	memcpy(&arp.arp_dev,iface,strlen(iface));
	int error=ioctl(inetsock,SIOCGARP,&arp);
	/*Cache ARP*/
	if(error==0)
	{
		//printf("Already in cache");
		memcpy(dest->receive_mac,&arp.arp_ha.sa_data,ETH_ADDR_LEN);
		close(inetsock);
		return 1;
	}

	if(errno==6)
	{
		/*Fallimento -> Dati non presenti nella cache -> Richiesta ARP*/
		//perror("");
		//printf("Sending an arp request...");
		fd=socket(AF_PACKET,SOCK_DGRAM,htons(ETH_P_ARP));
		if(fd<0)
		{
			perror("Error");
			close(inetsock);
			return -1;
		}
		int ciclo=0;
		arp_hdr risposta[sizeof(arp_hdr)];
		//Setting timer
		struct timeval tv;
		tv.tv_sec=30;
		tv.tv_usec=0;
		if(sendto(fd,(void*)&arpr,sizeof(arpr),0,(struct sockaddr*)&addr,sizeof(addr))<0)
		{
			perror("Error");
			close(inetsock);
			close(fd);
			return -1;
		}
		fd_set reading_set;
		FD_ZERO(&reading_set);
		FD_SET(fd,&reading_set);
		int ind;
		do{
			if((ind=select(FD_SETSIZE,&reading_set,NULL,NULL,&tv))<0)
			{
				perror("Error");
				close(inetsock);
				close(fd);
				return -1;
			}
			if (ind==0)
			{
				printf("No answer from remote host... retrying...\n");
				if(sendto(fd,(void*)&arpr,sizeof(arpr),0,(struct sockaddr*)&addr,sizeof(addr))<0)
				{
					perror("Error");
					close(inetsock);
					close(fd);
					return -1;
				}
				ciclo++;
				tv.tv_sec=30;
				tv.tv_usec=0;
				FD_ZERO(&reading_set);
				FD_SET(fd,&reading_set);
			}
			else
			{
				if(recv(fd,(void*)&risposta,sizeof(risposta),0)<0)
				{
					perror("Error");
					close(inetsock);
					close(fd);
					return -1;
				}
				if(ntohs(risposta->opcode) == ARPOP_REPLY)
					if(risposta->sender_ip[0] == arpr.target_ip[0] && risposta->sender_ip[1] == arpr.target_ip[1] && risposta->sender_ip[2] == arpr.target_ip[2] && risposta->sender_ip[3] == arpr.target_ip[3]) 
						ciclo=20;
				FD_ZERO(&reading_set);
				FD_SET(fd,&reading_set);
			}
		}while(ciclo<10);
		if(ciclo!=20)
		{
			fprintf(stderr,"Error: during ARP request\n");
			return -1;
		}
		//printf("Risposta ricevuta\n");
		//printf("Destination Address:%d.%d.%0d.%d",risposta.sender_ip[0],risposta.sender_ip[1],risposta.sender_ip[2],risposta.sender_ip[3]);
		//printf("\t-> %02X:%02X:%02X:%02X:%02X:%02X\n",risposta.sender_mac[0],risposta.sender_mac[1],risposta.sender_mac[2],risposta.sender_mac[3],risposta.sender_mac[4],risposta.sender_mac[5]);
		//Aggiungere alla cache ARP
		struct arpreq insert;
		memset(&insert, 0, sizeof(insert));
		insert.arp_ha.sa_family = ARPHRD_ETHER;
		memcpy(&insert.arp_ha.sa_data, risposta->sender_mac, 6);
		struct sockaddr_in *in = (struct sockaddr_in*) &insert.arp_pa;
		in->sin_addr.s_addr = dest->destIp;
		in->sin_family = AF_INET;
		insert.arp_flags=ATF_COM;
		memcpy(insert.arp_dev,iface,strlen(iface)+1);
		if(ioctl(fd, SIOCSARP, &insert) < 0)
			perror("Error");
		memcpy(dest->receive_mac,risposta->sender_mac,ETH_ADDR_LEN);
		close(inetsock);
		close(fd);
		return 1;
	}
	else
	{
		//printf("errno:\n",errno);
		perror("Error");
		close(inetsock);
		close(fd);
		return -1;
	}
}

int PSend(uint8_t *buffer, size_t length, unsigned char* hwdest,char *iface)
{
	struct ifreq ifr;
	/*Socket*/
	int sock=socket(AF_PACKET,SOCK_RAW,htons(ETH_P_ALL));
	if (sock==-1)
	{
		perror("Error");
		return -1;
	}
	/*Interface*/
	memset (&ifr, 0, sizeof (ifr));
  	snprintf (ifr.ifr_name, sizeof (ifr.ifr_name), "%s", iface);
  	if (ioctl (sock, SIOCGIFINDEX, &ifr) < 0) {
    	perror ("Error");
    	return -1;
    }
    int ifindex=ifr.ifr_ifindex;
    /*sockaddr_ll*/
	struct sockaddr_ll addr;
	addr.sll_family=AF_PACKET;
	addr.sll_ifindex=ifindex;
	addr.sll_halen=ETH_ADDR_LEN;
	addr.sll_protocol=htons(ETH_P_ALL);
	memcpy(&addr.sll_addr,hwdest,ETH_ADDR_LEN);
	//Invio
	PrintPacket(buffer,length);
	if(sendto(sock,buffer,length,0,(struct sockaddr*)&addr,sizeof(addr))<0)
	{
		perror("Error: Send failed");
		return -1;
	}
	return 0;
}