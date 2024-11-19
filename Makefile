imapcl : imapcl.o imap.o
	g++ -std=gnu++17 -Wall -Wextra -o imapcl imapcl.o imap.o -L/usr/lib -lcrypto -lssl

imap.o : imap.cc imap.hh
	g++ -std=gnu++17 -Wall -Wextra -c -o imap.o imap.cc

imapcl.o : imapcl.cc imap.hh
	g++ -std=gnu++17 -Wall -Wextra -c -o imapcl.o imapcl.cc

clean:
	rm *.o imapcl xdvory00.tar

tar:
	tar -cf xdvory00.tar Makefile imapcl.cc imap.cc imap.hh README manual.pdf
