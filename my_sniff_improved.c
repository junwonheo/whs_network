#include <stdlib.h>
#include <stdio.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <string.h> 

/* Ethernet header */
struct ethheader {
    u_char  ether_dhost[6]; /* destination host address */
    u_char  ether_shost[6]; /* source host address */
    u_short ether_type;     /* protocol type (IP, ARP, RARP, etc) */
};

/* IP Header */
struct ipheader {
    unsigned char      iph_ihl:4, //IP header length
                       iph_ver:4; //IP version
    unsigned char      iph_tos; //Type of service
    unsigned short int iph_len; //IP Packet length (data + header)
    unsigned short int iph_ident; //Identification
    unsigned short int iph_flag:3, //Fragmentation flags
                       iph_offset:13; //Flags offset
    unsigned char      iph_ttl; //Time to Live
    unsigned char      iph_protocol; //Protocol type
    unsigned short int iph_chksum; //IP datagram checksum
    struct  in_addr    iph_sourceip; //Source IP address
    struct  in_addr    iph_destip;   //Destination IP address
};

void got_packet(u_char *args, const struct pcap_pkthdr *header,
                              const u_char *packet)
{
    struct ethheader *eth = (struct ethheader *)packet;

    if (ntohs(eth->ether_type) == 0x0800) { // 0x0800 is IP type
        struct ipheader * ip = (struct ipheader *)
                               (packet + sizeof(struct ethheader)); 

        if (ip->iph_protocol == IPPROTO_TCP) {
            printf("Ethernet Header\n");
            printf("   Source MAC: ");
            for (int i = 0; i < 6; i++) {
                printf("%02x", eth->ether_shost[i]);
                if (i < 5) printf(":");
            }
            printf("\n");
            printf("   Destination MAC: ");
            for (int i = 0; i < 6; i++) {
                printf("%02x", eth->ether_dhost[i]);
                if (i < 5) printf(":");
            }
            printf("\n");

            printf("IP Header\n");
            printf("   Source IP: %s\n", inet_ntoa(ip->iph_sourceip));
            printf("   Destination IP: %s\n", inet_ntoa(ip->iph_destip));

            struct tcphdr *tcp = (struct tcphdr *)(packet + sizeof(struct ethheader) + sizeof(struct ipheader));

            printf("TCP Header\n");
            printf("   Source Port: %u\n", ntohs(tcp->th_sport));
            printf("   Destination Port: %u\n", ntohs(tcp->th_dport));

            
            int iph_len = ip->iph_ihl * 4;
            int data_len = ntohs(ip->iph_len) - iph_len - (tcp->th_off * 4);

           
            printf("Message Data\n");
            for (int i = 0; i < data_len; i++) {
                printf("%c", packet[iph_len + (tcp->th_off * 4) + i]);
            }
            printf("\n");
        }
    }
}

int main()
{
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char filter_exp[] = "tcp";
    bpf_u_int32 net;

    // Step 1: Open live pcap session on NIC with name enp0s3
    handle = pcap_open_live("eth0", BUFSIZ, 1, 1000, errbuf);

    // Step 2: Compile filter_exp into BPF psuedo-code
    pcap_compile(handle, &fp, filter_exp, 0, net);
    if (pcap_setfilter(handle, &fp) != 0) {
        pcap_perror(handle, "Error:");
        exit(EXIT_FAILURE);
    }

    // Step 3: Capture packets
    pcap_loop(handle, -1, got_packet, NULL);

    pcap_close(handle);   // Close the handle
    return 0;
}
