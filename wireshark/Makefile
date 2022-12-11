CC = gcc
CFLAGS = 
CLIBS = 
CMDS  = rawsocket

all : $(CMDS)

rawsocket:rawsocket.o
	gcc -o rawsocket.c rawsocket.o

rawsocket.o:rawsocket.c
	gcc -c rawsocket.c

clean :
	rm $(CMDS)