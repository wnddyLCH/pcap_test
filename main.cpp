#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>

#define ETHER_ADDR_LEN	6
#define SIZE_ETHERNET 14
#define TCP_HEADER_LENGTH 20
#define IP_HL(ip)		(((ip)->ip_vhl) & 0x0f)

void print_ethernet(u_char *n);

struct sniff_ethernet
{
    uint8_t ether_dhost[ETHER_ADDR_LEN]; /* Destination host address */
    uint8_t ether_shost[ETHER_ADDR_LEN]; /* Source host address */
    uint16_t ether_type; /* IP? ARP? RARP? etc */
}sniff_ethernet;


    /* IP header */
    struct sniff_ip
    {
        u_char ip_vhl;		/* version << 4 | header length >> 2 */
        u_char ip_tos;		/* type of service */
        u_short ip_len;		/* total length */
        u_short ip_id;		/* identification */
        u_short ip_off;		/* fragment offset field */
        u_char ip_ttl;		/* time to live */
        u_char ip_p;		/* protocol */
        u_short ip_sum;		/* checksum */
        struct in_addr {
            uint8_t ip_src[4];
            uint8_t ip_dst[4];
            }in_addr;/* source and dest address */
    }sniff_ip;

    /* TCP header */
    typedef u_int tcp_seq;


    struct sniff_tcp {
        uint16_t th_sport;	/* source port */
        uint16_t th_dport;	/* destination port */
        tcp_seq th_seq;		/* sequence number */
        tcp_seq th_ack;		/* acknowledgement number */
        u_char th_offx2;	/* data offset, rsvd */
        u_char th_flags;
        u_short th_win;		/* window */
        u_short th_sum;		/* checksum */
        u_short th_urp;		/* urgent pointer */
}sniff_tcp;


void usage() {
  printf("syntax: pcap_test <interface>\n");
  printf("sample: pcap_test wlan0\n");
}

 struct sniff_ethernet *eth;
 struct sniff_ip *ip;
 struct sniff_tcp *tcp;
 const u_char *payload;

 u_int size_tcp;
 u_int size_ip;

void print_ethernet(uint8_t *ether)
{
    printf("%02x:%02x:%02x:%02x:%02x:%02x\n",ether[0], ether[1], ether[2], ether[3], ether[4], ether[5]);
}

void store_ethernet(const u_char *packet)
{


    printf("Destination MAC : ");
    print_ethernet(eth->ether_dhost);
    printf("Source MAC : ");
    print_ethernet(eth->ether_shost);
    printf("Type : %04x\n", eth->ether_type);
}

void print_ip(const u_char *ip)
{
     printf("%d.%d.%d.%d\n",ip[0], ip[1], ip[2], ip[3]);
}

void store_ip(const u_char *packet)
{
    ip=(struct sniff_ip*)packet;

   // printf("%02x\n", ip->ip_vhl);

    printf("source ip : ");
    print_ip(ip->in_addr.ip_src);
    printf("destination ip : ");
    print_ip(ip->in_addr.ip_dst);
}

/*void print_port(const u_short *port)
{
    printf("%02x %02x", port[0], port[1]);
}*/

void store_tcp(const u_char *packet)
{
    tcp=(struct sniff_tcp*)packet;

   // printf("%2x\n", tcp->th_win);
    printf("source port : %d\n", ntohs(tcp->th_sport));
    printf("destination port : %d\n", ntohs(tcp->th_dport));

}

void print_tcp_data(const u_char *packet, int size)
{
    printf("TCP DATA content : ");
    size < 10 ? size : size=10;
    for(int i=0;i<size;i++)
    {
        printf("%02x ", packet[i]);
    }
    printf("\n");
}

int main(int argc, char* argv[])
{
  if (argc != 2) {
    usage();
    return -1;
  }

  char* dev = argv[1];
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
  }

  while (true)
  {
     printf("============================\n");
    struct pcap_pkthdr* header;
    const u_char* packet;
    int res = pcap_next_ex(handle, &header, &packet);
    if (res == 0) continue;
    if (res == -1 || res == -2) break;
    printf("%u bytes captured\n", header->caplen);

    eth=(struct sniff_ethernet*)packet;
    store_ethernet(packet);
    if(eth->ether_type==0x08)
    {
        //packet=packet + 14;
        //ip=(struct sniff_ip*)(packet+SIZE_ETHERNET);
        packet=packet+SIZE_ETHERNET;
        store_ip(packet);
    }
    size_ip=IP_HL(ip)*4;
    if(ip->ip_p==0x06)
    {
        //packet=packet+34;
        //tcp=(struct sniff_tcp*)packet+SIZE_ETHERNET+size_ip;
        packet=packet+size_ip;
        store_tcp(packet);
    }
   // size_tcp=TH_OFF(tcp)*4;
    //payload=(u_char *)(packet+SIZE_ETHERNET+size_ip+TCP_HEADER_LENGTH);
    packet=packet+size_ip;
    int size=(header->caplen)-(SIZE_ETHERNET+size_ip+TCP_HEADER_LENGTH);
    printf("TCP data size : %u\n", (header->caplen)-(SIZE_ETHERNET+size_ip+TCP_HEADER_LENGTH));
    if((header->caplen)-(SIZE_ETHERNET+size_ip+TCP_HEADER_LENGTH)>0)
    {
        //packet=packet+34+size_tcp;
        print_tcp_data(packet,size);
    }

    printf("============================");
    printf("\n\n");
  }

  pcap_close(handle);
  return 0;
}

