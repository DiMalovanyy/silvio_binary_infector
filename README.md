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

## Example

![Alt Text](https://github.com/DiMalovanyy/silvio_binary_infector/raw/master/demo/Silvio_infector_demo.gif "Example gif")
