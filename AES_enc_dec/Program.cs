using System;
using System.IO;
using System.Security.Cryptography;

namespace AES_enc_dec
{
    internal class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("\r\n░█████╗░███████╗░██████╗░░░░░░███████╗███╗░░██╗░█████╗░░░░░██╗██████╗░███████╗░█████╗░\r\n██╔══██╗██╔════╝██╔════╝░░░░░░██╔════╝████╗░██║██╔══██╗░░░██╔╝██╔══██╗██╔════╝██╔══██╗\r\n███████║█████╗░░╚█████╗░█████╗█████╗░░██╔██╗██║██║░░╚═╝░░██╔╝░██║░░██║█████╗░░██║░░╚═╝\r\n██╔══██║██╔══╝░░░╚═══██╗╚════╝██╔══╝░░██║╚████║██║░░██╗░██╔╝░░██║░░██║██╔══╝░░██║░░██╗\r\n██║░░██║███████╗██████╔╝░░░░░░███████╗██║░╚███║╚█████╔╝██╔╝░░░██████╔╝███████╗╚█████╔╝\r\n╚═╝░░╚═╝╚══════╝╚═════╝░░░░░░░╚══════╝╚═╝░░╚══╝░╚════╝░╚═╝░░░░╚═════╝░╚══════╝░╚════╝░\n");
            Console.WriteLine("Выберите действие:");
            Console.WriteLine("1. Зашифровать файл");
            Console.WriteLine("2. Расшифровать файл");
            Console.WriteLine("3. Зашифровать директорию и её содержимое");
            Console.WriteLine("4. Расшифровать директорию и её содержимое");
            ret:
            try
            {
                int choice = int.Parse(Console.ReadLine());
                if (choice == 1)
                {
                    Console.Write("Введите полное имя входного файла (путь и расширение): ");
                    string inputFile = Console.ReadLine();
                    Console.Write("Введите полное имя выходного файла (путь и расширение): ");
                    string outputFile = Console.ReadLine();

                    byte[] key = GenerateRandomAESKey();
                    string keyBase64 = Convert.ToBase64String(key);

                    Console.WriteLine("Сгенерированный ключ: " + keyBase64);

                    EncryptFile(inputFile, outputFile, keyBase64);
                    Console.WriteLine("Файл успешно зашифрован.");
                    Console.WriteLine("Нажмите Enter для выхода...");
                    while (true)
                    {
                        var keypress = Console.ReadKey().Key;
                        if (keypress == ConsoleKey.Enter)
                            break;
                    }
                }
                else if (choice == 2)
                {
                    Console.Write("Введите полное имя зашифрованного файла (путь и расширение): ");
                    string inputFile = Console.ReadLine();
                    Console.Write("Введите полное имя файла для расшифровки (путь и расширение): ");
                    string outputFile = Console.ReadLine();
                    Console.Write("Введите ключ (строка Base64): ");
                    string key = Console.ReadLine();

                    DecryptFile(inputFile, outputFile, key);
                    Console.WriteLine("Файл успешно расшифрован.");
                    Console.WriteLine("Нажмите Enter для выхода...");
                    while (true)
                    {
                        var keypress = Console.ReadKey().Key;
                        if (keypress == ConsoleKey.Enter)
                            break;
                    }
                }
                else if (choice == 3)
                {
                    Console.Write("Введите полное имя входной директории: ");
                    string inputDirectory = Console.ReadLine();
                    Console.Write("Введите полное имя выходной директории: ");
                    string outputDirectory = Console.ReadLine();

                    byte[] key = GenerateRandomAESKey();
                    string keyBase64 = Convert.ToBase64String(key);

                    Console.WriteLine("Сгенерированный ключ: " + keyBase64);

                    EncryptDirectory(inputDirectory, outputDirectory, keyBase64);
                    Console.WriteLine("Директория успешно зашифрована.");
                    Console.WriteLine("Нажмите Enter для выхода...");
                    while (true)
                    {
                        var keypress = Console.ReadKey().Key;
                        if (keypress == ConsoleKey.Enter)
                            break;
                    }
                }
                else if (choice == 4)
                {
                    Console.Write("Введите полное имя зашифрованной директории: ");
                    string inputDirectory = Console.ReadLine();
                    Console.Write("Введите полное имя директории для расшифровки: ");
                    string outputDirectory = Console.ReadLine();
                    Console.Write("Введите ключ (строка Base64): ");
                    string key = Console.ReadLine();

                    DecryptDirectory(inputDirectory, outputDirectory, key);
                    Console.WriteLine("Директория успешно расшифрована.");
                    Console.WriteLine("Нажмите Enter для выхода...");
                    while (true)
                    {
                        var keypress = Console.ReadKey().Key;
                        if (keypress == ConsoleKey.Enter)
                            break;
                    }
                }
                else
                {
                    Console.WriteLine("Неверный выбор.");
                }
            }
            catch (Exception)
            {
                Console.WriteLine("Укажите один из вариантов цифрой");
                goto ret;
            }     
        }

        static void EncryptFile(string inputFile, string outputFile, string key)
        {
            byte[] keyBytes = GetValidKey(key);

            if (keyBytes == null)
            {
                Console.WriteLine("Неверный ключ.");
                return;
            }

            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = keyBytes;
                aesAlg.GenerateIV();

                using (FileStream fsInput = new FileStream(inputFile, FileMode.Open))
                using (FileStream fsOutput = new FileStream(outputFile, FileMode.Create))
                using (ICryptoTransform encryptor = aesAlg.CreateEncryptor())
                using (CryptoStream cryptoStream = new CryptoStream(fsOutput, encryptor, CryptoStreamMode.Write))
                {
                    fsOutput.Write(aesAlg.IV, 0, aesAlg.IV.Length);

                    byte[] buffer = new byte[1024];
                    int bytesRead;

                    while ((bytesRead = fsInput.Read(buffer, 0, buffer.Length)) > 0)
                    {
                        cryptoStream.Write(buffer, 0, bytesRead);
                    }
                }
            }
            // Удаление оригинального файла после шифрования
            File.Delete(inputFile);
        }

        static void DecryptFile(string inputFile, string outputFile, string key)
        {
            byte[] keyBytes = GetValidKey(key);

            if (keyBytes == null)
            {
                Console.WriteLine("Неверный ключ.");
                return;
            }

            using (Aes aesAlg = Aes.Create())
            {
                byte[] iv = new byte[16];

                using (FileStream fsInput = new FileStream(inputFile, FileMode.Open))
                using (FileStream fsOutput = new FileStream(outputFile, FileMode.Create))
                {
                    fsInput.Read(iv, 0, iv.Length);

                    aesAlg.Key = keyBytes;
                    aesAlg.IV = iv;

                    using (ICryptoTransform decryptor = aesAlg.CreateDecryptor())
                    using (CryptoStream cryptoStream = new CryptoStream(fsOutput, decryptor, CryptoStreamMode.Write))
                    {
                        byte[] buffer = new byte[1024];
                        int bytesRead;

                        while ((bytesRead = fsInput.Read(buffer, 0, buffer.Length)) > 0)
                        {
                            cryptoStream.Write(buffer, 0, bytesRead);
                        }
                    }
                }
                // Удаление оригинального файла после расшифрования
                File.Delete(inputFile);
            }
        }

        static void EncryptDirectory(string inputDirectory, string outputDirectory, string key)
        {
            // Создайте выходную директорию, если она не существует
            Directory.CreateDirectory(outputDirectory);

            // Получите список файлов во входной директории
            string[] files = Directory.GetFiles(inputDirectory);

            foreach (string inputFile in files)
            {
                // Генерируйте имя выходного файла
                string fileName = Path.GetFileName(inputFile);
                string outputFile = Path.Combine(outputDirectory, fileName);

                // Зашифруйте файл
                EncryptFile(inputFile, outputFile, key);
            }

            // Получите список поддиректорий
            string[] subdirectories = Directory.GetDirectories(inputDirectory);

            foreach (string subdirectory in subdirectories)
            {
                // Генерируйте имя выходной поддиректории
                string subdirectoryName = Path.GetFileName(subdirectory);
                string outputSubdirectory = Path.Combine(outputDirectory, subdirectoryName);

                // Рекурсивно вызовите EncryptDirectory для поддиректории
                EncryptDirectory(subdirectory, outputSubdirectory, key);
            }
            // Удаление оригинального директории после шифрования
            Directory.Delete(inputDirectory);
        }

        static void DecryptDirectory(string inputDirectory, string outputDirectory, string key)
        {
            // Создайте выходную директорию, если она не существует
            Directory.CreateDirectory(outputDirectory);

            // Получите список файлов во входной директории
            string[] files = Directory.GetFiles(inputDirectory);

            foreach (string inputFile in files)
            {
                // Генерируйте имя выходного файла
                string fileName = Path.GetFileName(inputFile);
                string outputFile = Path.Combine(outputDirectory, fileName);

                // Расшифруйте файл
                DecryptFile(inputFile, outputFile, key);
            }

            // Получите список поддиректорий
            string[] subdirectories = Directory.GetDirectories(inputDirectory);

            foreach (string subdirectory in subdirectories)
            {
                // Генерируйте имя выходной поддиректории
                string subdirectoryName = Path.GetFileName(subdirectory);
                string outputSubdirectory = Path.Combine(outputDirectory, subdirectoryName);

                // Рекурсивно вызовите DecryptDirectory для поддиректории
                DecryptDirectory(subdirectory, outputSubdirectory, key);
            }
            // Удаление оригинального директории после расшифрования
            Directory.Delete(inputDirectory);
        }

        static byte[] GetValidKey(string key)
        {
            byte[] keyBytes = null;

            while (true)
            {
                try
                {
                    keyBytes = Convert.FromBase64String(key);
                    break;
                }
                catch (FormatException)
                {
                    Console.WriteLine("Ошибка: Недопустимая строка Base64. Введите ключ (строка Base64): ");
                    key = Console.ReadLine();
                }
            }

            return keyBytes;
        }

        static byte[] GenerateRandomAESKey()
        {
            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.KeySize = 256; // Устанавливаем размер ключа на 256 бит
                aesAlg.GenerateKey();
                return aesAlg.Key;
            }
        }
    }
}
