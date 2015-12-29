# src/Makefile

# pem2der Makefile for Linux

# Sébastien Millet, December 2015

# FORTIFYFLAGS = -Wunreachable-code -Wformat=2 \
#     -D_FORTIFY_SOURCE=2 -fstack-protector --param ssp-buffer-size=4 \
#     -fPIE -pie -Wl,-z,relro,-z,now
CPP = gcc
CPPFLAGS = -g -O2 -Wall -Wextra -Wuninitialized -Wshadow $(FORTIFYFLAGS)
LINKERFLAGS = -g -O2 -Wall -Wextra -Wuninitialized -Wshadow $(FORTIFYFLAGS) -lcrypto
OFLAG = -o

.SUFFIXES : .o .c .h
.c.o :
	$(CPP) $(FORTIFYFLAGS) $(CPPFLAGS) -c $<

all : pem2der

pem2der : pem2der.o ppem.o
	$(CPP) pem2der.o ppem.o $(LINKERFLAGS) $(OFLAG)$@

.PHONY: all clean mrproper

mrproper : clean

clean :
	rm -f *.o
	rm -f pem2der

