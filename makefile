LDLIBS += -lpcap

all: deauth-attack

mac.o : mac.h mac.cpp

deauth-attack : Deauth_Attack.o mac.o
	$(LINK.cc) $^ $(LOADLIBES) $(LDLIBS) -o $@

clean:
	rm -f deauth-attack *.o
