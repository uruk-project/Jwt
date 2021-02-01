using System;
using System.Security.Cryptography;
using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Diagnosers;
using JsonWebToken.Cryptography;

namespace JsonWebToken.Performance
{
    [MemoryDiagnoser]
    public class Pbkdf2Benchmark
    {
        private static readonly byte[] salt = new byte[16] { 217, 96, 147, 112, 150, 117, 70, 247, 127, 8, 155, 137, 174, 42, 80, 215 };
        private static readonly byte[] password = Utf8.GetBytes("Thus from my lips, by yours, my sin is purged.");

        [Benchmark(Baseline = true)]
        public byte[] Core()
        {
            using var pbkdf2_managed = new Rfc2898DeriveBytes(password, salt, 4096, HashAlgorithmName.SHA256);
            return pbkdf2_managed.GetBytes(16);
        }

        [Benchmark(Baseline = false)]
        public void Managed()
        {
            Span<byte> result2 = stackalloc byte[16];
            Pbkdf2.DeriveKey(password, salt, Sha256.Shared, 4096, result2);
        }
    }
}
