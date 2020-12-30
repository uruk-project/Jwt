using System;
using System.IO;
using System.Security.Cryptography.X509Certificates;

namespace JsonWebToken.Tools.Jwk
{
    internal class FileStore : IStore
    {
        public X509Certificate2 LoadX509(string inputPath, string? password)
        {
            return new X509Certificate2(inputPath, password);
        }

        public string Read(string inputPath)
        {
            if (!File.Exists(inputPath))
            {
                throw new InvalidOperationException($"The file {inputPath} does not exist.");
            }

            return File.ReadAllText(inputPath);
        }

        public void Write(string outputPath, string key, bool force)
        {
            if (File.Exists(outputPath) && !force)
            {
                throw new InvalidOperationException($"The file {outputPath} already exist. Use the parameter --force for overwriting the existing file.");
            }

            File.WriteAllText(outputPath, key);
        }
    }
}