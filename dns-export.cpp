/**
 * @file dns-export.cpp
 * @author Petr Sopf (xsopfp00)
 * @brief Main file for parsing arguments and callling functions based on options set
 */

#include <iostream>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <getopt.h>
#include <vector>
#include <pcap.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <sys/socket.h>
#include <arpa/inet.h> // for inet_ntoa()
#include <net/ethernet.h>
#include <netinet/ip_icmp.h>   //Provides declarations for icmp header
#include <netinet/udp.h>   //Provides declarations for udp header
#include <netinet/tcp.h>   //Provides declarations for tcp header
#include <netinet/ip.h>

#include "headers/dns-export.h"

using namespace std;

int main(int argc, char **argv) {
    //Options variables
    bool pcapFileSet = false;
    bool interfaceSet = false;
    bool syslogServerSet = false;
    bool isTimeSet = false;

    //Program argument values
    std::string pcapFile;
    std::string interface;
    std::string syslogServer;
    int statsTime = 60;

    int c;
    opterr = 0;

    while ((c = getopt(argc, argv, "r:i:s:t:")) != -1) {
        switch (c) {
            case 'r':
                pcapFileSet = true;
                pcapFile = optarg;
                break;
            case 'i':
                interfaceSet = true;
                interface = optarg;
                break;
            case 's':
                syslogServerSet = true;
                syslogServer = optarg;
                break;
            case 't':
                isTimeSet = true;
                char *ptr;
                statsTime = static_cast<int>(strtol(optarg, &ptr, 10));
                if (strlen(ptr) != 0) {
                    fprintf(stderr, "ERROR: Time must be integer!\n");
                    return 1;
                }
                break;
            case '?': //Check for unknown parameters
                if (optopt == 'r' || optopt == 'i' || optopt == 's' || optopt == 't') {
                    fprintf(stderr, "ERROR: Option %c requires an argument.\n", optopt);
                } else if (isprint(optopt)) {
                    fprintf(stderr, "ERROR: Unknown option `-%c'.\n", optopt);
                } else {
                    fprintf(stderr, "ERROR: Unknown option character `\\x%x'.\n", optopt);
                }
                return 1;
            default:
                abort();
        }
    }

    //Validate options
    if (pcapFileSet && interfaceSet) {
        fprintf(stderr, "ERROR: Option -i can't be used together with option -r!\n");
        return 1;
    } else if (pcapFileSet && isTimeSet) {
        fprintf(stderr, "ERROR: Option -t can't be used together with option -r!\n");
        return 1;
    } else if (!pcapFileSet && !interfaceSet && !syslogServerSet && !isTimeSet) {
        fprintf(stdout, "No arguments specified!\n");
        return 0;
    } else if (!pcapFileSet && !isTimeSet) {
        fprintf(stderr, "ERROR: You have to specify -r or -i option!\n");
        return 1;
    }

    //Execute based on specified options
    if (pcapFileSet) {
        parsePcapFile(pcapFile.c_str());
    }

    return 0;
}

void parsePcapFile(const char *pcapFile) {
    //Create error buff
    char errbuf[PCAP_ERRBUF_SIZE];

    //File handler
    pcap_t *fileHandler;

    //Open pcap file
    if ((fileHandler = pcap_open_offline(pcapFile, errbuf)) == NULL) {
        fprintf(stderr, "ERROR: Could not open specified pcap file (%s)!\n", errbuf);
        exit(1);
    }

    //Parse packets
    pcap_loop(fileHandler, 0, packetHandler, NULL);

    /*
    struct pcap_pkthdr header;
    const u_char *packet;
    struct ether_header *etherHeader;
    struct ip *myIP;
    u_int sizeIP;
    struct DNS_HEADER *dnsHeader;
    int answersCount;
    int i = 0;
    while ((packet = pcap_next(fileHandler, &header)) != NULL && i < 3) {
        etherHeader = (struct ether_header *) packet;
        switch (ntohs(etherHeader->ether_type)) {
            case ETHERTYPE_IP: //IPv4
                myIP = (struct ip *) (packet + SIZE_ETHERNET);
                sizeIP = myIP->ip_hl * 4;

                //Switch for protocol
                switch (myIP->ip_p) {
                    case 6: //TCP protocol
                        break;
                    case 17: //UDP protocol
                        dnsHeader = (struct DNS_HEADER *) (packet + SIZE_ETHERNET + sizeIP + 8);
                        answersCount = ntohs(dnsHeader->AnswerCount);

                        unsigned char *b = malloc((unsigned char *)strlen(packet));
                        memcpy(b, packet, strlen(packet));
                        unsigned char *data = &b[SIZE_ETHERNET + sizeIP + 8 + sizeof(dnsHeader) + sizeof(DNS_QUESTION)];
                        unsigned char *links_start = &b[SIZE_ETHERNET + sizeIP + 8 + sizeof(dnsHeader) - 12];

                        if (answersCount > 0) {
                            //Parse queries
                            int nameLen = 0;
                            std::string name = parse_name(data, links_start, &nameLen);
                            printf("NAME %s\n s: %i", name.c_str(), nameLen);

                            print_buf("test", data, 200);

                            //struct DNS_RECORD answers[answersCount];
                            //parse_data(answers, 1, data, links_start);
                        }
                        break;
                }

                break;
        }
        i++;
    }*/

    //Close file
    pcap_close(fileHandler);
}

static void print_buf(const char *title, const unsigned char *buf, size_t buf_len) {
    size_t i = 0;
    fprintf(stdout, "%s\n", title);
    for (i = 0; i < buf_len; ++i)
        fprintf(stdout, "%02X%s", buf[i],
                (i + 1) % 16 == 0 ? "\r\n" : " ");

}

void packetHandler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    //Check if is an IP packet
    struct ether_header *etherHeader;
    etherHeader = (struct ether_header *) packet;
    if (ntohs(etherHeader->ether_type) != ETHERTYPE_IP) {
        return;
    }

    const u_char *ipHeader;
    ipHeader = packet + 14;

    u_char protocol = *(ipHeader + 9);
    if (protocol == IPPROTO_TCP) {
        printf("TCP!\n");
        return;
    } else if (protocol == IPPROTO_UDP) {
        parsePacketUDP(packet, header->len);
        return;
    }
}

void parsePacketUDP(const u_char *buff, int len) {
    unsigned short iphdrlen;

    struct iphdr *iph = (struct iphdr *) (buff + sizeof(struct ethhdr));
    iphdrlen = iph->ihl * 4;

    struct udphdr *udph = (struct udphdr *) (buff + iphdrlen + sizeof(struct ethhdr));

    int header_size = sizeof(struct ethhdr) + iphdrlen + sizeof udph;

    print_buf("test", buff + header_size, static_cast<size_t>(len - header_size));
}

/**
 * Parses name from DNS answer
 */
std::string parse_name(unsigned char *data, unsigned char *links_start, int *nameLen) {
    bool link = false;
    bool linkDone = false;

    int linkValue = 0;
    int size = 0;
    *nameLen = 0;
    std::string name;

    while (*data != '\0') {
        if (link) {
            linkValue += *data;
            *nameLen = 2;
            linkDone = true;
        } else {
            name += *data;
        }

        if (*data >= 192) {
            link = true;
            linkValue += *data - 192;
            if (name.length() == 1) {
                name = "";
            } else {
                name = name.substr(0, name.size() - 1);
            }
        }

        ++size;
        data += 1;

        if (link && linkDone) {
            data = &links_start[linkValue];
            link = false;
            linkValue = 0;
            linkDone = false;
        }
    }

    if (name.empty()) {
        name = ".";
        *nameLen = 1;
    } else {
        name = name_from_dns_format(name);
    }

    return name;
}

/**
 * Parses DNS answers and stores it to data_place
 */
void parse_data(struct DNS_RECORD *data_place, int count, unsigned char *data, unsigned char *links_start) {
    int nameLen = 0;

    for (int i = 0; i < count; i++) {
        print_buf("Tst", data, 200);
        data_place[i].DataName = parse_name(data, links_start, &nameLen);
        data += nameLen;

        data_place[i].Data = (struct DNS_RECORD_DATA *) (data);
        data += sizeof(struct DNS_RECORD_DATA);

        size_t answer_length = ntohs(data_place[i].Data->DataLength);
        data_place[i].Rdata = (unsigned char *) malloc(answer_length);

        for (unsigned int ii = 0; ii < answer_length; ii++) {
            data_place[i].Rdata[ii] = data[ii];
        }


        data += answer_length;
        printf("\nLen: %i name: %s\n", static_cast<int>(answer_length), data_place[i].DataName.c_str());
    }
}

/**
 * Converts name in DNS format back to readable format
 */
std::string name_from_dns_format(std::string dns_name) {
    std::string name;
    unsigned int position = 0;
    std::vector<int> dots;

    for (char c : dns_name) {
        if (isprint(c)) {
            name += c;
        } else {
            dots.push_back(c);
        }

        ++position;
    }

    position = 0;
    for (int pos : dots) {
        position += pos;
        name.insert(position, ".");
        ++position;
    }

    return name;
}