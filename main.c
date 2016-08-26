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

void packet_handler (u_char *user, const struct pcap_pkthdr *h, const u_char *bytes) {
	const struct ether_header *eth_hdr = (const struct ether_header *) bytes;
	if (h->caplen < MIN_PKT_SZ || ntohs(eth_hdr->ether_type) != ETHERTYPE_IP) return;

	const struct iphdr *ip_hdr = (const struct iphdr *)(((const uint8_t *)eth_hdr) + sizeof(struct ether_header));
	const size_t ip_hdr_sz = ((size_t)ip_hdr->ihl) * 4L;
	if (ip_hdr->version != 4 || ip_hdr_sz < sizeof(struct iphdr) || ip_hdr->protocol != IPPROTO_TCP) return;

	// total pkt len chk
	if (ntohl(ip_hdr->tot_len) < (ip_hdr_sz + sizeof(struct tcphdr))) return;
	puts("TCP-0");

	if (h->caplen < sizeof(struct ether_header) + (size_t)ntohl(ip_hdr->tot_len)) return;
	puts("TCP-1");

	const size_t total_pkt_sz = sizeof(struct ether_header) + ((size_t)ip_hdr->tot_len);

	const struct tcphdr *tcp_hdr = (const struct tcphdr *)(((const uint8_t *)ip_hdr) + (ip_hdr->ihl * 4));
	const size_t tcp_hdr_sz = (size_t)(tcp_hdr->th_off) * 4L;
	if (total_pkt_sz < (sizeof(struct ether_header) + ip_hdr_sz + tcp_hdr_sz)) return;
	puts("TCP-2");

	const uint8_t *app_data = ((const uint8_t *)tcp_hdr) + tcp_hdr_sz;
	const size_t app_sz = ((size_t)ip_hdr->tot_len) - ip_hdr_sz - tcp_hdr_sz;

	/** Begin app processing **/

	// ACK, !SYN, !FIN, !RST, dst port 80
	if (!(tcp_hdr->th_flags & TH_ACK)
			|| (tcp_hdr->th_flags & TH_SYN)
			|| (tcp_hdr->th_flags & TH_FIN)
			|| (tcp_hdr->th_flags & TH_RST)
			|| tcp_hdr->th_dport != 80)
		return;

	puts("APP");
	
	if (app_sz > 4 && tcp_hdr->th_seq == 1 && memcmp(app_data, "GET ", 4) == 0) {
		puts("hello");
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

	err = pcap_loop(p_hl, -1, &packet_handler, NULL);

	if (err == -1) {
		pcap_perror(p_hl, argv[0]);
	}
	pcap_freecode(&prog);
	pcap_close(p_hl);

	return err < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}
