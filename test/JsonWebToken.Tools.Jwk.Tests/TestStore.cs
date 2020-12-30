using System;
using System.Security.Cryptography.X509Certificates;

namespace JsonWebToken.Tools.Jwk.Tests
{
    internal class TestStore : IStore
    {
        private readonly string _input;
        private readonly string? _certificateRaw;

        public bool WasRead { get; private set; }
        public bool WasWritten { get; private set; }

        public TestStore(string? input, string? certificateRaw = null)
        {
            _input = input ?? "";
            _certificateRaw = certificateRaw;
        }

        public string? Output { get; private set; }

        public string Read(string inputPath)
        {
            WasRead = true;
            return _input;
        }

        public void Write(string outputPath, string key, bool force)
        {
            WasWritten = true;
            Output = key;
        }

        public X509Certificate2 LoadX509(string inputPath, string? password)
        {
            WasRead = true;
            return new X509Certificate2(Convert.FromBase64String(_certificateRaw!), password, X509KeyStorageFlags.PersistKeySet | X509KeyStorageFlags.Exportable);
        }
    }
}
