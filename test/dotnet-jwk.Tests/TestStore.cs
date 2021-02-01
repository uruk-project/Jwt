using System;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;

namespace JsonWebToken.Tools.Jwk.Tests
{
    internal class TestStore : IStore
    {
        private readonly string _input;
        private readonly string? _certificateRaw;

        public string? file1;
        public string? file2;

        public bool WasRead { get; private set; }
        public bool WasWritten { get; private set; }

        public TestStore(string? input = null, string? certificateRaw = null)
        {
            _input = input ?? "";
            _certificateRaw = certificateRaw;
        }

        public string? Output { get; private set; }

        public Task<string> Read(string inputPath)
        {
            WasRead = true;
            return Task.FromResult(_input);
        }

        public Task Write(string outputPath, string key, bool force)
        {
            if (file1 is null)
            {
                file1 = outputPath;
            }else if(file2 is null)
            {
                file2 = outputPath;
            }
            else
            {
                throw new Xunit.Sdk.XunitException();
            }

            WasWritten = true;
            Output = key;
            return Task.CompletedTask;
        }

        public Task<X509Certificate2> LoadX509(string inputPath, string? password)
        {
            WasRead = true;
            return Task.FromResult(new X509Certificate2(Convert.FromBase64String(_certificateRaw!), password, X509KeyStorageFlags.PersistKeySet | X509KeyStorageFlags.Exportable));
        }
    }
}
