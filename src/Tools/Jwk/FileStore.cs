using System;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;

namespace JsonWebToken.Tools.Jwk
{
    internal class FileStore : IStore
    {
        public Task<X509Certificate2> LoadX509(string inputPath, string? password)
        {
            return Task.FromResult(new X509Certificate2(inputPath, password));
        }

        public Task<string> Read(string inputPath)
        {
            if (!File.Exists(inputPath))
            {
                throw new InvalidOperationException($"The file {inputPath} does not exist.");
            }

            return File.ReadAllTextAsync(inputPath);
        }

        public Task Write(string outputPath, string key, bool force)
        {
            if (File.Exists(outputPath) && !force)
            {
                throw new InvalidOperationException($"The file {outputPath} already exist. Use the parameter --force for overwriting the existing file.");
            }

            return File.WriteAllTextAsync(outputPath, key);
        }
    }
}