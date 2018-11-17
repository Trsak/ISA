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
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <sstream>
#include <algorithm>
#include <iostream>
#include <netdb.h>

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
    std::string interfaceName;
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
                interfaceName = optarg;
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
    } else if (!pcapFileSet && !interfaceSet) {
        fprintf(stderr, "ERROR: You have to specify -r or -i option!\n");
        return 1;
    }

    //Create syslog server connection
    if (syslogServerSet) {
        if (inet_pton(AF_INET, syslogServer.c_str(), &(sysServer.ipv4.sin_addr)) != 0) {
            sysServer.type = SYSLOG_IPV4;
        } else if (inet_pton(AF_INET6, syslogServer.c_str(), &(sysServer.ipv6.sin6_addr)) != 0) {
            sysServer.type = SYSLOG_IPV6;
        } else {
            struct hostent *syslogHostent = gethostbyname(syslogServer.c_str());
            if (!syslogHostent || syslogHostent->h_addr_list[0] == NULL) {
                fprintf(stderr, "ERROR: Syslog server must be IPv4, IPv6 or hostname!\n");
                return 1;
            }

            char *address = inet_ntoa((struct in_addr) *((struct in_addr *) syslogHostent->h_addr_list[0]));

            if (inet_pton(AF_INET, address, &(sysServer.ipv4.sin_addr)) != 0) {
                sysServer.type = SYSLOG_IPV4;
            } else if (inet_pton(AF_INET6, address, &(sysServer.ipv6.sin6_addr)) != 0) {
                sysServer.type = SYSLOG_IPV6;
            } else {
                fprintf(stderr, "ERROR: Syslog server must be IPv4, IPv6 or hostname!\n");
                return 1;
            }
        }

        int fd = socket(AF_INET, SOCK_DGRAM, 0);
        if (fd < 0) {
            fprintf(stderr, "ERROR: Can not create socket!\n");
            return 1;
        }

        const char *msg = "test";

        bzero(&syslogServerAddr, sizeof(syslogServerAddr));
        syslogServerAddr.sin_family = AF_INET;
        syslogServerAddr.sin_addr = sysServer.ipv4.sin_addr;
        syslogServerAddr.sin_port = htons(514);
        if (sendto(fd, msg, strlen(msg) + 1, 0, (sockaddr * ) & syslogServerAddr, sizeof(syslogServerAddr)) < 0) {
            perror("cannot send message");
            return false;
        }
    }

    //Create handler
    pcap_t *handler;

    //Create error buff
    char errbuf[PCAP_ERRBUF_SIZE];
    bpf_u_int32 ip, subnetMask;

    if (pcapFileSet) { //.pcap file
        if ((handler = pcap_open_offline(pcapFile.c_str(), errbuf)) == NULL) {
            fprintf(stderr, "ERROR: Could't open specified pcap file \"%s\" (%s)!\n", pcapFile.c_str(), errbuf);
            exit(1);
        }

        ip = 0;
        subnetMask = 0;
    } else if (interfaceSet) { //Sniff on interface
        if ((handler = pcap_open_live(interfaceName.c_str(), BUFSIZ, 1, 1000, errbuf)) == NULL) {
            fprintf(stderr, "ERROR: Couldn't sniff on given interface \"%s\" (%s)!\n", interfaceName.c_str(), errbuf);
            exit(1);
        }

        if (pcap_lookupnet(interfaceName.c_str(), &ip, &subnetMask, errbuf) == -1) {
            ip = 0;
            subnetMask = 0;
        }
    }

    //Set DNS filters
    struct bpf_program filter;
    char filterString[] = "port 53"; //Only DNS port

    if (pcap_compile(handler, &filter, filterString, 0, ip) == -1) {
        fprintf(stderr, "ERROR: Bad filter - %s\n", pcap_geterr(handler));
        exit(1);
    }

    if (pcap_setfilter(handler, &filter) == -1) {
        fprintf(stderr, "ERROR: Couldn't set filter - %s\n", pcap_geterr(handler));
        exit(1);
    }

    //Start parsing packets
    pcap_loop(handler, -1, parsePackets, NULL);

    //Parsing done, close handler
    if (handler != NULL) {
        pcap_close(handler);
    }

    if (!syslogServerSet) {
        printAllStatsToStdout();
    } else {
        sendAllStatsToSyslog();
    }

    return 0;
}

void sendAllStatsToSyslog() {
    for (Answer answer : answersVector) {
        printf("%s %i\n", answer.stringAnswer.c_str(), answer.count);
    }
}

void printAllStatsToStdout() {
    for (Answer answer : answersVector) {
        printf("%s %i\n", answer.stringAnswer.c_str(), answer.count);
    }
}

static void print_buf(const char *title, const unsigned char *buf, size_t buf_len) {
    size_t i = 0;
    fprintf(stdout, "%s\n", title);
    for (i = 0; i < buf_len; ++i)
        fprintf(stdout, "%02X%s", buf[i],
                (i + 1) % 16 == 0 ? "\r\n" : " ");

}

void parsePackets(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    (void) args;
    (void) header;
    /*static int i = 0;
    i++;
    if (i > 3) return;*/

    struct ether_header *etherHeader;
    struct ip *myIP;
    struct DNS_HEADER *dnsHeader;
    int answersCount, questionsCount;
    u_int sizeIP;
    etherHeader = (struct ether_header *) packet;

    switch (ntohs(etherHeader->ether_type)) {
        case ETHERTYPE_IP: //IPv4
            myIP = (struct ip *) (packet + SIZE_ETHERNET);
            sizeIP = myIP->ip_hl * 4;

            switch (myIP->ip_p) {
                case 6: //TCP protocol
                    break;
                case 17: //UDP protocol
                    dnsHeader = (struct DNS_HEADER *) (packet + SIZE_ETHERNET + sizeIP + 8);
                    answersCount = ntohs(dnsHeader->AnswerCount);
                    if (answersCount > 0) {
                        const unsigned char *data =
                                packet + SIZE_ETHERNET + sizeIP + 8 + sizeof(dnsHeader) + sizeof(DNS_QUESTION);

                        const unsigned char *answers = data;
                        //We have to skip all Questions in packet
                        questionsCount = ntohs(dnsHeader->QuestionCount);

                        int QNameLen = 0;
                        while (questionsCount > 0) {
                            while (data[QNameLen] != 0) {
                                QNameLen += 1;
                            }

                            answers += QNameLen + 1 + sizeof(DNS_QUESTION);
                            --questionsCount;
                        }

                        struct DNS_RECORD allAnswers[answersCount];
                        parseDNS(allAnswers, answersCount, answers, packet + SIZE_ETHERNET + sizeIP + 8);
                        for (int i = 0; i < answersCount; i++) {
                            saveAnswer(allAnswers[i], packet + SIZE_ETHERNET + sizeIP + 8);
                        }
                    }
                    break;
            }
            break;
    }
}

int getAnswerCount(std::string answer) {
    for (vector<Answer>::reverse_iterator i = answersVector.rbegin(); i != answersVector.rend(); ++i) {
        if (answer.compare(i->stringAnswer) == 0) {
            return 1 + i->count;
        }
    }

    return 0;
}

void saveAnswerToVector(std::string answer) {
    Answer finalAnswer;
    finalAnswer.stringAnswer = answer;
    finalAnswer.count = getAnswerCount(answer);
    answersVector.push_back(finalAnswer);
}

void saveAnswer(struct DNS_RECORD answer, const unsigned char *links_start) {
    int answer_type = ntohs(answer.Data->DataType);
    int nameLen = 0;
    std::string finalAnswerString;

    switch (answer_type) { //Switch DNS types
        case 1: { //TYPE: A
            char ipv4[INET_ADDRSTRLEN];
            struct in_addr ipv4_addr;
            memcpy(&ipv4_addr, answer.Rdata, ntohs(answer.Data->DataLength));
            inet_ntop(AF_INET, &ipv4_addr, ipv4, INET_ADDRSTRLEN);
            finalAnswerString = answer.DataName + " A " + ipv4;
            saveAnswerToVector(finalAnswerString);
            break;
        }
        case 2: { //TYPE: NS
            std::string ns = parse_name(answer.Rdata, links_start, &nameLen);
            finalAnswerString = answer.DataName + " NS " + ns;
            saveAnswerToVector(finalAnswerString);
            break;
        }
        case 5: { //TYPE: CNAME
            std::string cname = parse_name(answer.Rdata, links_start, &nameLen);
            finalAnswerString = answer.DataName + " CNAME " + cname;
            saveAnswerToVector(finalAnswerString);
            break;
        }
        case 12: { //TYPE: PTR
            std::string ptr = parse_name(answer.Rdata, links_start, &nameLen);
            finalAnswerString = answer.DataName + " PTR " + ptr;
            saveAnswerToVector(finalAnswerString);
            break;
        }
        case 28: { //TYPE: AAAA
            char ipv6[INET6_ADDRSTRLEN];
            struct in6_addr ipv6_addr;
            memcpy(&ipv6_addr, answer.Rdata, ntohs(answer.Data->DataLength));
            inet_ntop(AF_INET6, &ipv6_addr, ipv6, INET6_ADDRSTRLEN);
            finalAnswerString = answer.DataName + " AAAA " + ipv6;
            saveAnswerToVector(finalAnswerString);
            break;
        }
        default:
            break;
    }
}

void parseDNS(struct DNS_RECORD *allAnswers, int count, const unsigned char *data, const unsigned char *links_start) {
    int nameLen = 0;

    for (int i = 0; i < count; i++) {
        allAnswers[i].DataName = parse_name(data, links_start, &nameLen);
        allAnswers[i].DataName = allAnswers[i].DataName.substr(0, allAnswers[i].DataName.size() - 1);
        data += nameLen;

        allAnswers[i].Data = (struct DNS_RECORD_DATA *) (data);
        data += sizeof(struct DNS_RECORD_DATA);

        size_t answer_length = ntohs(allAnswers[i].Data->DataLength);
        allAnswers[i].Rdata = (unsigned char *) malloc(answer_length);

        for (unsigned int ii = 0; ii < answer_length; ii++) {
            allAnswers[i].Rdata[ii] = data[ii];
        }

        data += answer_length;
    }
}

std::string parse_name(const unsigned char *data, const unsigned char *links_start, int *nameLen) {
    bool link = false;
    bool linkDone = false;

    int linkValue = 0;
    int size = 0;
    *nameLen = 0;
    std::string name;

    int index = 0;
    while (data[index] != '\0') {
        if (link) {
            linkValue += data[index];
            *nameLen = 2;
            linkDone = true;
        } else {
            name += data[index];
        }

        if (data[index] >= 192) {
            link = true;
            linkValue += data[index] - 192;
            if (name.length() == 1) {
                name = "";
            } else {
                name = name.substr(0, name.size() - 1);
            }
        }

        ++size;
        index += 1;

        if (link && linkDone) {
            data = &links_start[linkValue];
            index = 0;
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

std::string name_to_dns_format(std::string name) {
    std::string dns_name;

    auto exploded = explode(name, '.');

    for (auto piece : exploded) {
        int num = piece.length();
        dns_name += num;
        dns_name += piece;
    }

    return dns_name;
}

/**
 * Explodes string into vectory by delimeter
 * @source https://stackoverflow.com/a/12967010
 */
std::vector <std::string> explode(std::string const &s, char delim) {
    std::vector <std::string> result;
    std::istringstream iss(s);

    for (std::string token; std::getline(iss, token, delim);) {
        result.push_back(std::move(token));
    }

    return result;
}