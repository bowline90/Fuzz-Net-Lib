#ifndef _NET2015
#define _NET2015
//Definizione header dati
#define HEADER_IP 20
#define HEADER_TCP 20
#define HEADER_UDP 8
#define HEADER_SCTP 12
#define HEADER_ICMP 8
#define HEADER_ETH 14

#define ETH_ADDR_LEN 6
#include <sys/types.h>
#include <net/if.h>

typedef struct _arp_hdr arp_hdr;
struct _arp_hdr {
  u_int16_t htype;
  u_int16_t ptype;
  u_int8_t hlen;
  u_int8_t plen;
  u_int16_t opcode;
  unsigned char sender_mac[6];
  unsigned char sender_ip[4];
  unsigned char target_mac[6];
  unsigned char target_ip[4];
};

struct hwinfo{
	unsigned char sender_mac[6];
	unsigned char receive_mac[6];
	u_int32_t destIp;
};

typedef struct eth_header_t{
	u_int8_t destination[6];
	u_int8_t source[6];
	u_int16_t length;
	u_int8_t DSAP;
	u_int8_t SSAP;
	u_int16_t control;
}eth_header;

typedef struct _eth_header_tx{
	unsigned char destination[6];
	unsigned char source[6];
	u_int16_t length;
}eth_header_tx;

typedef struct ip_header_t{
#if __BYTE_ORDER == __LITTLE_ENDIAN
	unsigned int IhL:4;												/*Lunghezza header*/
	unsigned int Version:4;											/*Versione*/
	u_int8_t Reserved:2,Affidability:1,Thr:1,Latenza:1,Prec:3; /*TOS*/
#elif __BYTE_ORDER == __BIG_ENDIAN
	unsigned int Version:4;											/*Versione*/
	unsigned int IhL:4;												/*Lunghezza header*/
	u_int8_t Prec:3, Latenza:1, Thr:1, Affidability:1, Reserved:2;	/*TOS*/
#else
#error "BYTE_ORDER NOT DEFINED"
#endif
	u_int16_t Tot_Length;											/*Lunghezza totale del pacchetto, header+dati*/
	u_int16_t Identification;										/*Identificazione dei frammenti*/
#if __BYTE_ORDER ==__LITTLE_ENDIAN
	u_int16_t Offset:13,MF:1,DF:1,Res:1;
#elif __BYTE_ORDER == __BIG_ENDIAN
	u_int16_t Res:1,DF:1,MF:1,Offset:13;							/*Flags da splittare*/
#else
#error "BYTE_ORDER NOT DEFINED"
#endif
	u_int8_t TTL;													/*Time To Live*/
	u_int8_t Protocol;												/*Protocollo di livello superiore*/
	u_int16_t HeaderChecksum;										/*Checksum*/
	u_int32_t SourceAddress;										/*Indirizzo sorgente*/
	u_int32_t DestAddress;											/*Indirizzo destinazione*/
}ip_header;

typedef struct tcp_header_t{
	u_int16_t sourcePort;
	u_int16_t destPort;
	u_int32_t sequence;
	u_int32_t Ack;
#if __BYTE_ORDER == __LITTLE_ENDIAN
	u_int8_t Reserved:4,DataOffset:4;
	u_int8_t FIN:1,SYN:1,RST:1,PSH:1,ACK:1,URG:1,ECE:1,CWR:1;
#elif __BYTE_ORDER == __BIG_ENDIAN
	u_int8_t DataOffset:4,Reserved:4;
	u_int8_t CWR:1,ECE:1,URG:1,ACK:1,PSH:1,RST:1,SYN:1,FIN:1;
#else
#error "BYTE_ORDER NOT DEFINED"
#endif
	u_int16_t WindowSize;
	u_int16_t Checksum;
	u_int16_t UrgentPointer;
}tcp_header;

typedef struct tcp_header_pseudo{
	u_int32_t sourceAddress;
	u_int32_t destAddress;
	u_int8_t zero;
	u_int8_t proto;
	u_int16_t tcplenght;
}pseudo_header_tcp;

typedef struct udp_header_t{
	u_int16_t sourcePort;
	u_int16_t destPort;
	u_int16_t lenght;
	u_int16_t Checksum;
}udp_header;

typedef struct sctp_header_t{
	u_int16_t sourcePort;
	u_int16_t destPort;
	u_int32_t verTag;
	u_int32_t Checksum;
}sctp_header;

typedef struct sctp_chunk_t{
	u_int8_t Type;
	u_int8_t Flags;
	u_int16_t Lenght;
	//Deve essere multiplo di 4 byte
}sctp_chunk;

typedef struct icmp_header_t{
	u_int8_t Type;
	u_int8_t Code;
	u_int16_t Checksum;
	u_int32_t Rest;
}icmp_header;

//Utility function
void checksumTCP(ip_header *ip,tcp_header *tcp,void* data,size_t lenght);
u_int16_t checksum (void * buffer, int bytes);
void PrintHeaderIp(ip_header *ip);
void PrintHeaderTCP(tcp_header *tcp);
void PrintHeaderUDP(udp_header *udp);
void PrintHeaderSCTP(sctp_header *sctp);
void PrintHeaderICMP(icmp_header*);
void PrintHeaderEth(eth_header_tx*);
void PrintArp(arp_hdr*);
void PrintPacket(u_int8_t *buffer,size_t length);
void list_interface(int);
//Create of stack
int FuzzyIP(char* iface,ip_header ip,int raw,void *head_protocol,void* data,size_t lenght);
int FuzzyEth_IP(u_int8_t *buffer,size_t length,char *iface,u_int32_t);
int resolution(char* iface,struct hwinfo* dest);
int PSend(u_int8_t *buffer, size_t length,unsigned char*,char*);
//sctp_chunk* Chunk_SCTP(size_t *len);
//int FuzzyIP_SCTP(int sock,struct ifreq ifr,ip_header ip,sctp_header *testa_sctp,sctp_chunk* data[],int nchunks,size_t tot_length);
#endif
