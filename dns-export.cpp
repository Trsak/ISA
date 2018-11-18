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
#include <netinet/ip6.h>
#include <sstream>
#include <algorithm>
#include <iostream>
#include <netdb.h>
#include <thread>
#include <chrono>
#include <csignal>
#include <ctime>
#include <unistd.h>
#include <limits.h>
#include <atomic>

#include "headers/dns-export.h"

using namespace std;

int main(int argc, char **argv) {
    //Register signals
    signal(SIGINT, sigtermSignalHandler);
    signal(SIGUSR1, sigusr1SignalHandler);

    //Options variables
    pcapFileSet = false;
    interfaceSet = false;
    syslogServerSet = false;
    isTimeSet = false;

    //Program argument values
    std::string pcapFile;
    std::string interfaceName;
    std::string syslogServer;
    statsTime = 60;

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

        if (sysServer.type == SYSLOG_IPV4) {
            fd = socket(AF_INET, SOCK_DGRAM, 0);
            if (fd < 0) {
                fprintf(stderr, "ERROR: Can't create socket!\n");
                return 1;
            }

            bzero(&syslogServerAddrv4, sizeof(syslogServerAddrv4));
            syslogServerAddrv4.sin_family = AF_INET;
            syslogServerAddrv4.sin_addr = sysServer.ipv4.sin_addr;
            syslogServerAddrv4.sin_port = htons(514);
        } else if (sysServer.type == SYSLOG_IPV6) {
            fd = socket(AF_INET6, SOCK_DGRAM, 0);
            if (fd < 0) {
                fprintf(stderr, "ERROR: Can't create socket!\n");
                return 1;
            }

            bzero(&syslogServerAddrv6, sizeof(syslogServerAddrv6));
            syslogServerAddrv6.sin6_family = AF_INET6;
            syslogServerAddrv6.sin6_addr = sysServer.ipv6.sin6_addr;
            syslogServerAddrv6.sin6_port = htons(514);
        }
    }

    //Create thread sending stats to syslog
    if (syslogServerSet && interfaceSet) {
        stopFlag = false;
        syslogThread = std::thread(syslogThreadSend);
    }

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

    if (syslogThread.joinable()) {
        stopFlag = true;
        syslogThread.join();
    }

    return 0;
}

void sigtermSignalHandler(int signum) {
    (void) signum;

    //Detach thread and signal it to end
    if (syslogThread.joinable()) {
        stopFlag = true;
        syslogThread.detach();
    }

    //Close handler
    if (handler != NULL) {
        pcap_close(handler);
    }

    exit(0);
}

void sigusr1SignalHandler(int signum) {
    (void) signum;
    printAllStatsToStdout();
}

void syslogThreadSend() {
    while (!stopFlag) {
        this_thread::sleep_for(std::chrono::seconds(statsTime));
        sendAllStatsToSyslog();
        if (stopFlag) {
            std::terminate();
        }
    }
}

void sendAllStatsToSyslog() {
    char hostname[HOST_NAME_MAX];
    gethostname(hostname, HOST_NAME_MAX);

    for (Answer answer : answersVector) {
        timeval curTime;
        gettimeofday(&curTime, NULL);
        int milli = curTime.tv_usec / 1000;
        char buffer[80];
        strftime(buffer, 80, "%FT%T", localtime(&curTime.tv_sec));
        char currentTime[84] = "";
        sprintf(currentTime, "%s.%dZ", buffer, milli);

        std::string message;
        message += "<134>1 ";
        message += currentTime;
        message += " ";
        message += hostname;
        message += " dns-export ";
        message += " - - - ";
        message += answer.stringAnswer;
        message += " ";
        message += std::to_string(answer.count);

        if (message.back() != '\0') {
            message += '\0';
        }

        if (sysServer.type == SYSLOG_IPV4) {
            sendto(fd, message.c_str(), message.length(), 0, (sockaddr * ) & syslogServerAddrv4,
                   sizeof(syslogServerAddrv4));
        } else if (sysServer.type == SYSLOG_IPV6) {
            sendto(fd, message.c_str(), message.length(), 0, (sockaddr * ) & syslogServerAddrv6,
                   sizeof(syslogServerAddrv6));
        }
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

    struct ether_header *etherHeader;
    struct ip *myIP;
    struct ip6_hdr *myIP6;
    const u_char *tcpHeader;
    const u_char *payload;
    int tcpHeaderLength;
    char transferProtocol;
    u_int sizeIP;
    etherHeader = (struct ether_header *) packet;

    switch (ntohs(etherHeader->ether_type)) {
        case ETHERTYPE_IP: //IPv4
        {
            myIP = (struct ip *) (packet + SIZE_ETHERNET);
            sizeIP = myIP->ip_hl * 4;
            transferProtocol = myIP->ip_p;
            break;
        }
        case ETHERTYPE_IPV6: //IPv6
        {
            myIP6 = (struct ip6_hdr *) (packet + SIZE_ETHERNET);
            sizeIP = 40;
            transferProtocol = (char) myIP6->ip6_ctlun.ip6_un1.ip6_un1_nxt;
            break;
        }
    }

    switch (transferProtocol) {
        case 6: //TCP protocol
        {
            if (header->caplen > 1500) break; //Fragmented TCP packet
            tcpHeader = packet + SIZE_ETHERNET + sizeIP;
            tcpHeaderLength = ((*(tcpHeader + 12)) & 0xF0) >> 4;
            tcpHeaderLength = tcpHeaderLength * 4;

            int totalHeadersSize = SIZE_ETHERNET + sizeIP + tcpHeaderLength;
            payload = packet + totalHeadersSize;

            parseDNSPacket(payload, true);
            break;
        }
        case 17: //UDP protocol
        {
            parseDNSPacket(packet + SIZE_ETHERNET + sizeIP + 8, false);
            break;
        }
        default:
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
    int size = 0;
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
            std::string ns = parseName(answer.Rdata, links_start, &nameLen, &size);
            finalAnswerString = answer.DataName + " NS " + ns;
            saveAnswerToVector(finalAnswerString);
            break;
        }
        case 5: { //TYPE: CNAME
            std::string cname = parseName(answer.Rdata, links_start, &nameLen, &size);
            finalAnswerString = answer.DataName + " CNAME " + cname;
            saveAnswerToVector(finalAnswerString);
            break;
        }
        case 6: { //TYPE: SOA
            std::string soa = parseName(answer.Rdata, links_start, &nameLen, &size);

            int offset = size;
            while (answer.Rdata[offset] != '\0') {
                offset++;
            }
            offset += 1;

            unsigned char *buf = answer.Rdata + offset;
            std::string mailboxString = parseName(buf, links_start, &nameLen, &size);
            offset += size;

            buf = answer.Rdata + offset;

            struct DNS_SOA_DATA *soaData = (struct DNS_SOA_DATA *) (answer.Rdata + offset);
            std::string sData = std::to_string(ntohl(soaData->SerialNumber)) + " ";
            sData += std::to_string(ntohl(soaData->RefreshInterval)) + " ";
            sData += std::to_string(ntohl(soaData->RetryInterval)) + " ";
            sData += std::to_string(ntohl(soaData->ExpireLimit)) + " ";
            sData += std::to_string(ntohl(soaData->MinimumTTL));

            finalAnswerString = answer.DataName + " SOA " + "\"" + soa + " " + mailboxString + sData + "\"";
            saveAnswerToVector(finalAnswerString);
            break;
        }
        case 12: { //TYPE: PTR
            std::string ptr = parseName(answer.Rdata, links_start, &nameLen, &size);
            finalAnswerString = answer.DataName + " PTR " + ptr;
            saveAnswerToVector(finalAnswerString);
            break;
        }
        case 15: { //TYPE: MX
            struct DNS_MX_DATA *mxData = (struct DNS_MX_DATA *) (answer.Rdata);
            std::string mx = parseName(answer.Rdata + 2, links_start, &nameLen, &size);
            finalAnswerString =
                    answer.DataName + " MX " + "\"" + std::to_string(ntohs(mxData->Preference)) + " " + mx + "\"";
            saveAnswerToVector(finalAnswerString);
            break;
        }
        case 16: { //TYPE: TXT
            int length = answer.Rdata[0];

            std::string txtMessage;
            for (int i = 1; i <= length; i += 1) {
                txtMessage.push_back(answer.Rdata[i]);
            }

            finalAnswerString = answer.DataName + " TXT " + "\"" + txtMessage + "\"";
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
        case 43: { //TYPE: DS
            struct DNS_DS_DATA *dsData = (struct DNS_DS_DATA *) (answer.Rdata);
            finalAnswerString = answer.DataName + " DS " + "\"";

            std::string tags = "0x";
            int i = 0;
            while (i < 2) {
                char buff[100];
                snprintf(buff, sizeof(buff), "%02x", answer.Rdata[i]);
                tags += buff;
                i++;
            }
            finalAnswerString += tags;
            finalAnswerString += " " + std::to_string(dsData->Algorithm);
            finalAnswerString += " " + std::to_string(dsData->DigestType);

            std::string digest;
            i = sizeof(DNS_DS_DATA);
            while (i < ntohs(answer.Data->DataLength)) {
                char buff[100];
                snprintf(buff, sizeof(buff), "%02x", answer.Rdata[i]);
                digest += buff;
                i++;
            }
            finalAnswerString += " " + digest;

            finalAnswerString += "\"";
            saveAnswerToVector(finalAnswerString);
            break;
        }
        case 46: { //TYPE: RRSIG
            struct DNS_RRSIG_DATA *rrsigData = (struct DNS_RRSIG_DATA *) (answer.Rdata);

            std::string typeCovered = dnsTypeNameById(htons(rrsigData->TypeCovered));
            finalAnswerString =
                    answer.DataName + " RRSIG " + "\"" + typeCovered;
            finalAnswerString += " " + std::to_string(rrsigData->Algorithm);
            finalAnswerString += " " + std::to_string(rrsigData->Labels);
            finalAnswerString += " " + std::to_string(ntohl(rrsigData->OriginalTTL));
            finalAnswerString += " " + std::to_string(ntohl(rrsigData->SignatureExpiration));
            finalAnswerString += " " + std::to_string(ntohl(rrsigData->SignatureInception));
            finalAnswerString += " " + std::to_string(htons(rrsigData->KeyTag));

            int namePos = sizeof(DNS_RRSIG_DATA);
            std::string signerName = parseName(answer.Rdata + namePos, links_start, &nameLen, &size);
            finalAnswerString += " " + signerName;

            std::string signature;
            int i = namePos + size + 1;
            while (i < ntohs(answer.Data->DataLength)) {
                char buff[100];
                snprintf(buff, sizeof(buff), "%02x", answer.Rdata[i]);
                signature += buff;
                i++;
            }
            finalAnswerString += " " + signature;

            finalAnswerString += "\"";
            saveAnswerToVector(finalAnswerString);
            break;
        }
        case 47: { //TYPE: NSEC
            std::string nsec = parseName(answer.Rdata, links_start, &nameLen, &size);
            finalAnswerString = answer.DataName + " NSEC " + "\"" + nsec;

            int i = size + 1;
            std::string types;
            while (i < ntohs(answer.Data->DataLength)) {
                char buff[100];
                snprintf(buff, sizeof(buff), "%02x", answer.Rdata[i]);
                types += buff;
                i++;
            }
            finalAnswerString += " " + types;

            finalAnswerString += "\"";
            saveAnswerToVector(finalAnswerString);
            break;
        }
        case 48: { //TYPE: DNSKEY
            struct DNS_DNSKEY_DATA *dnskeyData = (struct DNS_DNSKEY_DATA *) (answer.Rdata);

            finalAnswerString =
                    answer.DataName + " DNSKEY " + "\"";

            std::string flags = "0x";
            int i = 0;
            while (i < 2) {
                char buff[100];
                snprintf(buff, sizeof(buff), "%02x", answer.Rdata[i]);
                flags += buff;
                i++;
            }
            finalAnswerString += flags;
            finalAnswerString += " " + std::to_string(dnskeyData->Protocol);
            finalAnswerString += " " + std::to_string(dnskeyData->Algorithm) + " ";

            std::string publicKey;
            i = sizeof(DNS_DNSKEY_DATA);
            while (i < ntohs(answer.Data->DataLength)) {
                char buff[100];
                snprintf(buff, sizeof(buff), "%02x", answer.Rdata[i]);
                publicKey += buff;
                i++;
            }
            finalAnswerString += publicKey;

            finalAnswerString += "\"";
            saveAnswerToVector(finalAnswerString);
            break;
        }
        default:
            break;
    }
}

std::string dnsTypeNameById(int type) {
    std::string name;
    switch (type) {
        case 1:
            name = "A";
            break;
        case 2:
            name = "NS";
            break;
        case 5:
            name = "CNAME";
            break;
        case 6:
            name = "SOA";
            break;
        case 12:
            name = "PTR";
            break;
        case 15:
            name = "MX";
            break;
        case 16:
            name = "TXT";
            break;
        case 17:
            name = "RP";
            break;
        case 18:
            name = "AFSDB";
            break;
        case 24:
            name = "SIG";
            break;
        case 25:
            name = "KEY";
            break;
        case 26:
            name = "AAAA";
            break;
        case 29:
            name = "LOC";
            break;
        case 33:
            name = "SRV";
            break;
        case 35:
            name = "NAPTR";
            break;
        case 43:
            name = "DS";
            break;
        case 46:
            name = "RRSIG";
            break;
        case 47:
            name = "NSEC";
            break;
        case 48:
            name = "DNSKEY";
            break;
        case 49:
            name = "DHCID";
            break;
        case 50:
            name = "NSEC3";
            break;
        default:
            name = std::to_string(type);
    }

    return name;
}

void parseDNSPacket(const unsigned char *packet, bool isTCP) {
    int answersCount, questionsCount;
    struct DNS_HEADER *dnsHeader;

    if (isTCP) {
        packet += 2;
    }

    dnsHeader = (struct DNS_HEADER *) (packet);
    answersCount = ntohs(dnsHeader->AnswerCount);
    if (answersCount > 0) {
        const unsigned char *data =
                packet + sizeof(dnsHeader) + sizeof(DNS_QUESTION);

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
        parseDNS(allAnswers, answersCount, answers, packet);
        for (int i = 0; i < answersCount; i++) {
            saveAnswer(allAnswers[i], packet);
        }
    }
}

void parseDNS(struct DNS_RECORD *allAnswers, int count, const unsigned char *data, const unsigned char *links_start) {
    int nameLen = 0;
    int size = 0;

    for (int i = 0; i < count; i++) {
        allAnswers[i].DataName = parseName(data, links_start, &nameLen, &size);
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

std::string parseName(const unsigned char *data, const unsigned char *links_start, int *nameLen, int *size) {
    bool link = false;
    bool linkDone = false;

    int linkValue = 0;
    *nameLen = 0;
    *size = 0;
    std::string name;

    int index = 0;
    while (data[index] != '\0') {
        if (link) {
            linkValue += data[index];
            *nameLen = 2;
            linkDone = true;
            --(*size);
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
        index += 1;

        if (!link && !linkDone) {
            ++(*size);
        }

        if (link && linkDone) {
            data = &links_start[linkValue];
            index = 0;
            link = false;
            linkValue = 0;
            linkDone = false;
            --(*size);
        }
    }

    if (name.empty()) {
        name = ".";
        *nameLen = 1;
    } else {
        name = nameFromDnsFormat(name);
    }

    if (name.back() == '.') {
        name = name.substr(0, name.size() - 1);
    }
    return name;
}

std::string nameFromDnsFormat(std::string dns_name) {
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

std::string nameToDnsFormat(std::string name) {
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