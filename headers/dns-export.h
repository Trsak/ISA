/**
 * @file dns-export.h
 * @author Petr Sopf (xsopfp00)
 * @brief Header file for dns-export, contains global variables and structures
 */

#include <string>
#include <vector>

#ifndef ISA_DNS_EXPORT_H
#define ISA_DNS_EXPORT_H

//Syslog server ip protocol types
#define SYSLOG_IPV4 0
#define SYSLOG_IPV6 1

//Socket descriptor
int fd;

//Handler for pcap file or interface
pcap_t *handler;

//Mutex to access answers vector
std::mutex answersMutex;

//Atomic boolean
std::atomic<bool> stopFlag;

//Thread for sending syslog messages
std::thread syslogThread;

//Program arguments
int statsTime;
bool pcapFileSet;
bool interfaceSet;
bool syslogServerSet;
bool isTimeSet;

//Syslog server addresses
sockaddr_in syslogServerAddrv4;
sockaddr_in6 syslogServerAddrv6;

//Syslog server struct
typedef struct syslogServer {
    int type;
    struct sockaddr_in ipv4;
    struct sockaddr_in6 ipv6;
} sServer;

sServer sysServer;

//Answer struct
struct Answer {
    std::string stringAnswer;
    int count;
};

//Vector of all answers
std::vector <Answer> answersVector;

//Ethernet Header size
#define SIZE_ETHERNET 14

/**
 * @return void
 * @param signum Signal number
 *
 * Used to handle SIGTERM signal
 */
void sigtermSignalHandler(int signum);

/**
 * @return void
 * @param signum Signal number
 *
 * Used to handle SIGUSR1 signal
 */
void sigusr1SignalHandler(int signum);

/**
 * @return void
 * @param args Arguments
 * @param header Packet header
 * @param packet Packet buffer
 *
 * Function called for every packet to process.
 */
void parsePackets(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

/**
 * @return void
 * @param packet Packet buffer
 * @param isTCP True if packet is TSP
 *
 * Used to parse DNS packets.
 */
void parseDNSPacket(const unsigned char *packet, bool isTCP);

/**
 * @return void
 * @param allAnswers Array for storing answers
 * @param count Count of answers
 * @param data Packet buffer
 * @param links_start Buffer for links
 *
 * Used to parse DNS answers.
 */
void parseDNS(struct DNS_RECORD *allAnswers, int count, const unsigned char *data, const unsigned char *links_start);

/**
 * @return void
 *
 * Loops through all answers and sends them to syslog server.
 */
void sendAllStatsToSyslog();

/**
 * @return void
 *
 * Loops through all answers and print them to STDOUT.
 */
void printAllStatsToStdout();

/**
 * @return void
 *
 * Function to handle syslog thread.
 */
void syslogThreadSend();

/**
 * @return void
 * @param answer Answer DNS record
 * @param links_start Links buffer
 *
 * Saves answer to global vector.
 */
void saveAnswer(struct DNS_RECORD answer, const unsigned char *links_start);

/**
 * @return string DNS Name
 * @param type DNS type ID
 */
std::string dnsTypeNameById(int type);

/**
 * @return string Name in DNS format
 * @param name Name
 */
std::string nameToDnsFormat(std::string name);

/**
 * @return string Name
 * @param dns_name Name in DNS format
 */
std::string nameFromDnsFormat(std::string dns_name);

/**
 * @return string Parsed name
 * @param data Buffer
 * @param links_start Buffer for links
 * @param nameLen Name len
 * @param size Name size
 */
std::string parseName(const unsigned char *data, const unsigned char *links_start, int *nameLen, int *size);

/**
 * Explodes string into vectory by delimeter
 * @source https://stackoverflow.com/a/12967010
 */
std::vector <std::string> explode(std::string const &s, char delim);

/**
 * DNS STRUCTURES
 * Some of them taken from Microsoft library:
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
struct DNS_RRSIG_DATA {
    int TypeCovered : 16;
    int Algorithm : 8;
    int Labels : 8;
    long int OriginalTTL : 32;
    long int SignatureExpiration : 32;
    long int SignatureInception : 32;
    int KeyTag : 16;
};
#pragma pack(pop)

struct DNS_MX_DATA {
    int Preference : 16;
};

struct DNS_DS_DATA {
    unsigned int KeyTag : 16;
    int Algorithm : 8;
    int DigestType : 8;
};

struct DNS_DNSKEY_DATA {
    unsigned int Flags : 16;
    int Protocol : 8;
    int Algorithm : 8;
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

#endif //ISA_DNS_EXPORT_H
