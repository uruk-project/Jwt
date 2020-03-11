using System.Collections.Generic;
using System.Linq;
using System.Text;
using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Diagnosers;
using JsonWebToken.Internal;

namespace JsonWebToken.Performance
{
    [MemoryDiagnoser]
    public class AesEncryptorBenchmark
    {
        private static AesCbcEncryptor _encryptor;
#if NETCOREAPP3_0
        private static AesNiCbc128Encryptor _encryptorNi;
#endif
        private static byte[] ciphertext;
        private static byte[] nonce;

        static AesEncryptorBenchmark()
        {
            ciphertext = new byte[(2048 * 16 + 16) & ~15];
            var key = SymmetricJwk.GenerateKey(128);
            nonce = new byte[] { 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1 };
            _encryptor = new AesCbcEncryptor(key.K, EncryptionAlgorithm.Aes128CbcHmacSha256);
#if NETCOREAPP3_0
            _encryptorNi = new AesNiCbc128Encryptor(key.K);
#endif  
        }

        [Benchmark(Baseline = true)]
        [ArgumentsSource(nameof(GetData))]
        public void Encrypt(byte[] plaintext)
        {
            _encryptor.Encrypt(plaintext, nonce, ciphertext);
        }

#if NETCOREAPP3_0
        [Benchmark(Baseline = false)]
        [ArgumentsSource(nameof(GetData))]
        public void Encrypt_Simd(byte[] plaintext)
        {
            _encryptorNi.Encrypt(plaintext, nonce, ciphertext);
        }
#endif

        public static IEnumerable<byte[]> GetData()
        {
            yield return Encoding.UTF8.GetBytes(Enumerable.Repeat('a', 1).ToArray());
            yield return Encoding.UTF8.GetBytes(Enumerable.Repeat('a', 2048).ToArray());
            yield return Encoding.UTF8.GetBytes(Enumerable.Repeat('a', 2048 * 16).ToArray());
        }
    }
}
