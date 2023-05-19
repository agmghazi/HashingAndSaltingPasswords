using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace HashingAndSaltingPasswords
{
    internal class Program
    {
        static void Main(string[] args)
        {
            string key = "ashproghelpdotnetmania2022key123";
            string password = "ahemed1212";
            Console.WriteLine("normal text: " + password);
            string EncryptPass = Encrypt(password, key);
            Console.WriteLine("EncryptPass: " + EncryptPass);
            string DecryptPass = Decrypt(EncryptPass, key);
            Console.WriteLine("DecryptPass:  " + DecryptPass);
            Console.ReadLine();
        }

        public static string Encrypt(string text, string key)
        {
            byte[] iv = new byte[16];
            byte[] array;
            using (Aes aes = Aes.Create())
            {
                aes.Key = Encoding.UTF8.GetBytes(key);
                aes.IV = iv;
                ICryptoTransform encryptor = aes.CreateEncryptor(aes.Key, aes.IV);
                using MemoryStream ms = new MemoryStream();
                using CryptoStream cryptoStream = new CryptoStream((Stream)ms, encryptor, CryptoStreamMode.Write);
                using (StreamWriter streamWriter = new StreamWriter((Stream)cryptoStream))
                    streamWriter.Write(text);
              
                array = ms.ToArray();
            }
            return Convert.ToBase64String(array);
        }

        public static string Decrypt(string text, string key)
        {
            byte[] iv = new byte[16];
            byte[] buffer = Convert.FromBase64String(text);
            using (Aes aes = Aes.Create())
            {
                aes.Key = Encoding.UTF8.GetBytes(key);
                aes.IV = iv;
                ICryptoTransform decryptor = aes.CreateDecryptor(aes.Key, aes.IV);
                using MemoryStream ms = new MemoryStream(buffer);
                using CryptoStream cryptoStream = new CryptoStream((Stream)ms, decryptor, CryptoStreamMode.Read);
                using StreamReader sr = new StreamReader(cryptoStream);
                return sr.ReadToEnd();
            }
        }

    }
}
