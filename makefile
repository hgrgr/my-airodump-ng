LDLIBS += -lpcap

all: pcap-test

pcap-test: pcap-test.cpp myfunc.cpp

clean:
	rm -f pcap-test *.o
