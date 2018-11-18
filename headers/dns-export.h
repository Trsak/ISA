/**
 * @file dns-export.h
 * @author Petr Sopf (xsopfp00)
 * @brief Header file for dns-export, contains global variables
 */

#include <string>
#include <vector>

#ifndef ISA_DNS_EXPORT_H
#define ISA_DNS_EXPORT_H

#define SYSLOG_IPV4 0
#define SYSLOG_IPV6 1
int fd;

pcap_t *handler;

std::atomic<bool> stopFlag;

std::thread syslogThread;

int statsTime;
bool pcapFileSet;
bool interfaceSet;
bool syslogServerSet;
bool isTimeSet;

sockaddr_in syslogServerAddrv4;
sockaddr_in6 syslogServerAddrv6;

typedef struct syslogServer {
    int type;
    struct sockaddr_in ipv4;
    struct sockaddr_in6 ipv6;
} sServer;


sServer sysServer;

struct Answer {
    std::string stringAnswer;
    int count;
};

std::vector <Answer> answersVector;

//Ethernet Header size
#define SIZE_ETHERNET 14

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

struct DNS_MX_DATA {
    int Preference : 16;
};

struct DNS_SOA_DATA {
    unsigned long SerialNumber : 32;
    long int RefreshInterval : 32;
    long int RetryInterval : 32;
    long int ExpireLimit : 32;
    long int MinimumTTL : 32;
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

void parsePackets(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

void sigtermSignalHandler(int signum);

void sigusr1SignalHandler(int signum);

void parseDNSPacket(const unsigned char *packet, bool isTCP);

void parseDNS(struct DNS_RECORD *allAnswers, int count, const unsigned char *data, const unsigned char *links_start);

void sendAllStatsToSyslog();

void printAllStatsToStdout();

void syslogThreadSend();

std::string name_to_dns_format(std::string name);

std::string name_from_dns_format(std::string dns_name);

std::string parse_name(const unsigned char *data, const unsigned char *links_start, int *nameLen, int *size);

std::vector <std::string> explode(std::string const &s, char delim);

void saveAnswer(struct DNS_RECORD answer, const unsigned char *links_start);

#endif //ISA_DNS_EXPORT_H
