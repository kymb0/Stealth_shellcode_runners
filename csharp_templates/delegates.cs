using System;
using System.Runtime.InteropServices;

namespace a
{
class b
    {
        [DllImport("kernel32", SetLastError = true, CharSet = CharSet.Ansi)]
        static extern IntPtr LoadLibrary([MarshalAs(UnmanagedType.LPStr)] string lpFileName);

        [DllImport("kernel32", CharSet = CharSet.Ansi, ExactSpelling = true, SetLastError = true)]
        internal static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate int MessageBox(IntPtr hWnd, String text, String caption, int options);

        static void Main() 
        {
            static IntPtr getPtr(string dllName, string funcName)
        {

            IntPtr hModule = LoadLibrary(dllName);
            IntPtr Ptr = GetProcAddress(hModule, funcName);
            return Ptr;

        }
            IntPtr ptr1 = getPtr("user32.dll", "MessageBoxA");
            MessageBox mb = (MessageBox)Marshal.GetDelegateForFunctionPointer(ptr1, typeof(MessageBox));

            string a = "lol";
            string b = "hmm";
            uint c = 0;

            mb(IntPtr.Zero, a, b, 0);

     
        }
    }
}
