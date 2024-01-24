LDLIBS=-lpcap

all: deauth-attack

main.o: main.cpp

radiotap.o: radiotap.h radiotap.cpp

deauth-attack: main.o radiotap.o
	$(LINK.cc) $^ $(LOADLIBES) $(LDLIBS) -o $@

clean:
	rm -f deauth-attack *.o