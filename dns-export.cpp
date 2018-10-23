#include <iostream>
#include <string>
#include <stdbool.h>
#include <getopt.h>

using namespace std;

int main(int argc, char **argv)
{
    //Variables for parsing arguments
    bool pcapFileSet = false;
    bool interfaceSet = false;
    bool syslogServerSet = false;
    bool isTimeSet = false;

    //Program argument values
    string pcapFile;
    string interface;
    string syslogServer;
    int statsTime = 60;

    int c;
    opterr = 0;

    while ((c = getopt(argc, argv, "abc:")) != -1)
    {
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
                break;
            case '?':
                if (optopt == 'r' || optopt == 'i' || optopt == 's' || optopt == 't')
                    fprintf(stderr, "Option -%c requires an argument.\n", optopt);
                else if (isprint(optopt))
                    fprintf(stderr, "Unknown option `-%c'.\n", optopt);
                else
                    fprintf(stderr,
                            "Unknown option character `\\x%x'.\n",
                            optopt);
                return 1;
            default:
                abort();
        }
    }

    printf("%i %s %i %s %i %s %i %i", pcapFileSet, pcapFile.c_str(), interfaceSet, interface.c_str(), syslogServerSet, syslogServer.c_str(), isTimeSet, statsTime);

    return 0;
}