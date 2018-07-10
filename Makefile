.PHONY:all

all: tunneld lz4.so

tunneld:
	make -C silly/ linux
#make -C silly/ macosx

lz4.so: lualib-lz4.c lz4.c
	gcc -g -Wall -Isilly/lua/ -I./ --share  -fPIC -o $@ $^
	#gcc -g -Wall -Isilly/lua/ -I../lib/ -dynamiclib -fPIC -Wl,-undefined,dynamic_lookup -o $@ $^

