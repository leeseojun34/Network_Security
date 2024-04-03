#include <stdio.h>
#include <pcap.h>
#include "header_structs.h"

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet){

  struct ethheader *eth = (struct ethheader *)packet;
  struct ipheader *ip = (struct ipheader *)(packet + sizeof(struct ethheader));
  struct tcpheader *tcp = (struct tcpheader *)(packet + sizeof(struct ethheader) + ip->iph_ihl * 4);
  
  // Ethernet
  const unsigned char *src_mac = eth->ether_shost;
  const unsigned char *dest_mac = eth->ether_dhost;
  printf("Source MAC: %02X:%02X:%02X:%02X:%02X:%02X\n", src_mac[0], src_mac[1], src_mac[2], src_mac[3], src_mac[4], src_mac[5]);
  printf("Destination MAC: %02X:%02X:%02X:%02X:%02X:%02X\n", dest_mac[0], dest_mac[1], dest_mac[2], dest_mac[3], dest_mac[4], dest_mac[5]);

  // IP
  printf("Source IP: %s\n", inet_ntoa(ip->iph_sourceip));
  printf("Destination IP: %s\n", inet_ntoa(ip->iph_destip));

  // TCP
  printf("Source Port: %d\n", ntohs(tcp->tcp_sport));
  printf("Destination Port: %d\n", ntohs(tcp->tcp_dport));
	
  // Payload
  int max_payload_length = 64;
  int payload_length = ntohs(ip->iph_len) - (ip->iph_ihl * 4) - (tcp->tcp_offx2 >> 4) * 4;
  printf("Payload Data: ");
  if (payload_length <= max_payload_length) {
    for (int i = 0; i < payload_length; ++i) {
      printf("%02X ", packet[sizeof(struct ethheader) + ip->iph_ihl * 4 + (tcp->tcp_offx2 >> 4) * 4 + i]);
    }
  } else {
    for (int i = 0; i < max_payload_length; ++i) {
      printf("%02X ", packet[sizeof(struct ethheader) + ip->iph_ihl * 4 + (tcp->tcp_offx2 >> 4) * 4 + i]);
    }
    printf("... (추가 데이터 생략)");
  }
	
  printf("\n\n");
}

int main(){
  pcap_t *handle;
  char errbuf[PCAP_ERRBUF_SIZE];

  handle = pcap_open_live("ens33", BUFSIZ, 1, 1000, errbuf);

  pcap_loop(handle, 0, got_packet, NULL);

  pcap_close(handle);

  return 0;
}