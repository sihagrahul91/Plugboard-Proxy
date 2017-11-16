CC = gcc
LIBS = -lpthread -lcrypto

all: pbproxy
pbproxy: pbproxy.o 
	${CC} ${FLAGS} -o pbproxy pbproxy.o ${LIBS}
pbproxy.o: pbproxy.c
	${CC} ${FLAGS} -c pbproxy.c mystruct.h

clean:
	rm pbproxy.o pbproxy
