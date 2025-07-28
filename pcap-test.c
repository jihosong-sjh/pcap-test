#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <libnet.h>

void usage() {
	printf("syntax: pcap-test <interface>\n");
	printf("sample: pcap-test wlan0\n");
}

typedef struct {
	char* dev_;
} Param;

Param param = {
	.dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
	if (argc != 2) {
		usage();
		return false;
	}
	param->dev_ = argv[1];
	return true;
}

int main(int argc, char* argv[]) {
	if (!parse(&param, argc, argv))
		return -1;

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
		return -1;
	}

	while (true) {
		struct pcap_pkthdr* header;
		struct libnet_ethernet_hdr *eth_hdr;
		struct libnet_ipv4_hdr *ip_hdr;
		struct libnet_tcp_hdr *tcp_hdr;

		const u_char* packet;
		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));

			break;
		}

		eth_hdr = (struct libnet_ethernet_hdr*) packet;
		ip_hdr = (struct libnet_ipv4_hdr*) (packet + sizeof(*eth_hdr));
		tcp_hdr = (struct libnet_tcp_hdr*) (packet + sizeof(*eth_hdr) + (ip_hdr->ip_hl)*4);

		printf("%u bytes captured\n", header->caplen);
		
		printf("=====1. Ethernet=====");
		printf("\n");
		printf("src mac: ");
		for (int i=0; i<6; i++) {
			printf("%02x", eth_hdr->ether_shost[i]);
			if (i < 5) printf(":");
		}
		printf("\n");
		printf("dst mac: ");
		for (int i=0; i<6; i++) {
			printf("%02x", eth_hdr->ether_dhost[i]);
			if (i < 5) printf(":");
		}
		printf("\n");
		
		printf("=====2. Ipv4=====");
		printf("\n");
		uint8_t* src_ip_bytes = (uint8_t*)&ip_hdr->ip_src.s_addr;
		printf("src ip: %u.%u.%u.%u\n", src_ip_bytes[0], src_ip_bytes[1], src_ip_bytes[2], src_ip_bytes[3]);
		uint8_t* dst_ip_bytes = (uint8_t*)&ip_hdr->ip_dst.s_addr;
		printf("dst ip: %u.%u.%u.%u\n", dst_ip_bytes[0], dst_ip_bytes[1], dst_ip_bytes[2], dst_ip_bytes[3]);
		
		printf("=====3. TCP=====");
		printf("\n");
		uint16_t src_port = ntohs(tcp_hdr->th_sport);
		uint16_t dst_port = ntohs(tcp_hdr->th_dport);
		printf("src port: %u\n", src_port);
		printf("dst port: %u\n", dst_port);

		uint32_t data_offset = sizeof(struct libnet_ethernet_hdr) + (ip_hdr->ip_hl)*4 + (tcp_hdr->th_off)*4;
		printf("=====4. Payload (Data)=====\n");

        	if (header->caplen <= data_offset) {
			printf("Payload: 0");
		} else {
			uint32_t payload_total_len = header->caplen - data_offset;
			const u_char* payload = packet + data_offset;

			printf("Payload max 20bytes: ");
			for (int i=0; i < payload_total_len && i < 20; i++) {
				printf("%02x", payload[i]);
			}
			printf("\n");
		}
		printf("\n");
	}

	pcap_close(pcap);
}
