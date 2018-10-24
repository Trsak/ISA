/**
 * @file dns-export.h
 * @author Petr Sopf (xsopfp00)
 * @brief Header file for dns-export, contains global variables
 */

#include <string>

#ifndef ISA_DNS_EXPORT_H
#define ISA_DNS_EXPORT_H

/**
 * DNS STRUCTURES
 * @source https://msdn.microsoft.com/en-us/library/windows/desktop/ms682059(v=vs.85).aspx
 */
struct DNS_HEADER {
    unsigned short ID;

    unsigned char RecursionDesired : 1;
    unsigned char Truncation : 1;
    unsigned char Authoritative : 1;
    unsigned char Opcode : 4;
    unsigned char IsResponse : 1;

    unsigned char ResponseCode :4;
    unsigned char CheckingDisabled :1;
    unsigned char AuthenticatedData :1;
    unsigned char Reserved :1;
    unsigned char RecursionAvailable :1;

    unsigned short QuestionCount;
    unsigned short AnswerCount;
    unsigned short NameServerCount;
    unsigned short AdditionalCount;
};

struct DNS_QUESTION {
    unsigned short QuestionType;
    unsigned short QuestionClass;
};

#pragma pack(push, 1)
struct DNS_RECORD_DATA {
    unsigned short DataType;
    unsigned short DataClass;
    unsigned int DataTTL;
    unsigned short DataLength;
};
#pragma pack(pop)

struct DNS_RECORD {
    std::string DataName;
    struct DNS_RECORD_DATA *Data;
    unsigned char *Rdata;
};

std::string name_from_dns_format(std::string dns_name);

std::string parse_name(unsigned char *data, unsigned char *links_start, int *nameLen);

void parse_data(struct DNS_RECORD *data_place, int count, unsigned char *data, unsigned char *links_start);

void packetHandler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
/**
 * @brief Starts parsing of pcap file
 * @return void
 */
void parsePcapFile(const char *pcapFile);

void parsePacketUDP(const u_char *buff, int len);

#endif //ISA_DNS_EXPORT_H
