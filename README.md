## ISA - Export DNS informací pomocí protokolu Syslog
# Informace
Cílem projektu je vytvořit aplikaci, která bude umět zpracovávat data protokolu DNS (Domain Name System) a vybrané statistiky exportovat pomocí protokolu Syslog na centrální logovací server. 
# Překlad
 - Projekt lze přeložit příkazem **make**, který vytvoří spustitelný
   soubor (dns-export).
# Použití
     ./dns-export [-r file.pcap] [-i interface] [-s syslog-server] [-t seconds]
 - -r : zpracuje daný pcap soubor
 - -i : naslouchá na daném síťovém rozhraní a zpracovává DNS provoz
 - -s : hostname/ipv4/ipv6 adresa syslog serveru
 - -t : doba výpočtu statistik, výchozí hodnota 60s
