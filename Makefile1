
LIB_NAME?=hpslib

STATIC_NAME ?= lib$(LIB_NAME).a

all: static_library

static_library: 
	gcc -c *.c;
	ar  -cr $(STATIC_NAME) *.o;
	rm -rf ./lib/* ./include/*
	cp -af *.a ./lib/
	cp -af *.h ./include/

clean:
	rm -rf *.o
	rm -rf *.a  ./lib/* ./include/*
