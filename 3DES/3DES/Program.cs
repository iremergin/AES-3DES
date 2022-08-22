using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography;
using System.IO;
using static _3DES.TripleDes;

namespace _3DES
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("Lütfen kullanmak için bir şifre girin: ");
            string password = Console.ReadLine();
            Console.WriteLine("Lütfen şifrelemek için bir dize girin:");
            string plaintext = Console.ReadLine();
            Console.WriteLine("");

            Console.WriteLine("Şifrelenmiş dizeniz:");
            string encryptedstring = StringCipher.Encrypt(plaintext, password);
            Console.WriteLine(encryptedstring);
            Console.WriteLine("");

            Console.WriteLine("Şifresi çözülmüş dizeniz:");
            string decryptedstring = StringCipher.Decrypt(encryptedstring, password);
            Console.WriteLine(decryptedstring);
            Console.WriteLine("");

            Console.WriteLine("Çıkmak için herhangi bir tuşa basın...");
            Console.ReadLine();
        }
    }
    }

