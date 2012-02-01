LIBS=-lssh2
GHC=ghc $(LIBS) --make
HSFILES=Network/SSH/Client/LibSSH2/Conduit.hs

all: ssh-client

ssh-client: ssh-client.hs $(HSFILES)
	$(GHC) $<

clean:
	find . -name \*.hi -delete
	find . -name \*.o -delete
	rm -f ssh-client
