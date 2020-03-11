using System.Collections.Generic;
using System.Linq;
using System.Text;
using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Diagnosers;
using JsonWebToken.Internal;

namespace JsonWebToken.Performance
{
    [MemoryDiagnoser]
    public class AesDecryptorBenchmark
    {
        private static AesCbcEncryptor _encryptor;
        private static AesCbcDecryptor _decryptor;
#if NETCOREAPP3_0
        private static AesNiCbc128Decryptor _decryptorNi;
#endif
        private static byte[] plaintext;
        private static byte[] nonce;

        static AesDecryptorBenchmark()
        {
            plaintext = new byte[2048 * 16 + 16];
            var key = SymmetricJwk.GenerateKey(128);
            nonce = new byte[] { 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1 };
            _encryptor = new AesCbcEncryptor(key.K, EncryptionAlgorithm.Aes128CbcHmacSha256);
            _decryptor = new AesCbcDecryptor(key.K, EncryptionAlgorithm.Aes128CbcHmacSha256);
#if NETCOREAPP3_0
            _decryptorNi = new AesNiCbc128Decryptor(key.K);
#endif
        }

        [Benchmark(Baseline = true)]
        [ArgumentsSource(nameof(GetData))]
        public bool Decrypt(byte[] ciphertext)
        {
            return _decryptor.TryDecrypt(ciphertext, nonce, plaintext, out int bytesWritten);
        }

#if NETCOREAPP3_0
        [Benchmark(Baseline = false)]
        [ArgumentsSource(nameof(GetData))]
        public bool Decrypt_Simd(byte[] ciphertext)
        {
            return _decryptorNi.TryDecrypt(ciphertext, nonce, plaintext, out int bytesWritten);
        }

        public static IEnumerable<byte[]> GetData()
        {
            yield return GetCiphertext(Encoding.UTF8.GetBytes(Enumerable.Repeat('a', 1).ToArray()));
            yield return GetCiphertext(Encoding.UTF8.GetBytes(Enumerable.Repeat('a', 2048).ToArray()));
            yield return GetCiphertext(Encoding.UTF8.GetBytes(Enumerable.Repeat('a', 2048 * 16).ToArray()));
        }

        private static byte[] GetCiphertext(byte[] plaintext)
        {
           var ciphertext = (new byte[(plaintext.Length + 16) & ~15]);

            _encryptor.Encrypt(plaintext, nonce, ciphertext);
            return ciphertext;
        }
#endif
    }
}
