
DEBUG=-DDEBUG

all: infector payload victim

infector: infector.c
	gcc infector.c -o infector $(DEBUG)

payload: payload.c
	gcc payload.c -nostdlib -o payload -Wno-implicit-int

victim: victim.c
	gcc victim.c -o victim -no-pie -fno-pic

clean:
	rm -rf infector
	rm -rf payload
	rm -rf victim
	rm -rf *.o
	rm -rf .xyz.tempo.elf64

.PHONY: clean all
