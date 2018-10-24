PROG = dns-export
EXEC = $(PROG)
sources = $(PROG).cpp

CXX = g++
RM = rm -f

CFLAGS = -std=c++11 -Wall -Wextra
LDFLAGS = -lrt -pthread -lpcap

OBJFILES = $(sources:.c=.o)

.PHONY : all

all : $(EXEC)

%.o : %.c
	$(CXX) $(CFLAGS) -c $< -o $@

$(EXEC) : $(OBJFILES)
	$(CXX) $(CFLAGS) -o $@ $(OBJFILES) $(LDFLAGS)

clean:
	$(RM) *.o core *.out

cleanall: clean
	$(RM) $(EXEC)