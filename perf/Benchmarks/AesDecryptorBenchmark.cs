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
        private readonly static AesCbcEncryptor _encryptor;
        private readonly static AesCbcDecryptor _decryptor;
#if NETCOREAPP3_0
        private readonly static Aes128NiCbcDecryptor _decryptorNi;
#endif
        private readonly static byte[] plaintext;
        private readonly static byte[] nonce;
        private readonly static byte[] key;

        static AesDecryptorBenchmark()
        {
            plaintext = new byte[2048 * 16 + 16];
            key = SymmetricJwk.GenerateKey(128).AsSpan().ToArray();
            nonce = new byte[] { 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1 };
            _encryptor = new AesCbcEncryptor(EncryptionAlgorithm.Aes128CbcHmacSha256);
            _decryptor = new AesCbcDecryptor(key, EncryptionAlgorithm.Aes128CbcHmacSha256);
#if NETCOREAPP3_0
            _decryptorNi = new Aes128NiCbcDecryptor(key);
#endif
        }

        [Benchmark(Baseline = true)]
        [ArgumentsSource(nameof(GetData))]
        public bool Decrypt(Item data)
        {
            return _decryptor.TryDecrypt(data.Ciphertext, nonce, plaintext, out int bytesWritten);
        }

#if NETCOREAPP3_0
        [Benchmark(Baseline = false)]
        [ArgumentsSource(nameof(GetData))]
        public bool Decrypt_Simd(Item data)
        {
            return _decryptorNi.TryDecrypt(data.Ciphertext, nonce, plaintext, out int bytesWritten);
        }

        public static IEnumerable<Item> GetData()
        {
            yield return new Item(GetCiphertext(Encoding.UTF8.GetBytes(Enumerable.Repeat('a', 1).ToArray())));
            yield return new Item(GetCiphertext(Encoding.UTF8.GetBytes(Enumerable.Repeat('a', 2048).ToArray())));
            yield return new Item(GetCiphertext(Encoding.UTF8.GetBytes(Enumerable.Repeat('a', 2048 * 16).ToArray())));
        }

        private static byte[] GetCiphertext(byte[] plaintext)
        {
            var ciphertext = (new byte[(plaintext.Length + 16) & ~15]);

            _encryptor.Encrypt(key, plaintext, nonce, ciphertext);
            return ciphertext;
        }

        public class Item
        {
            public Item(byte[] ciphertext)
            {
                Ciphertext = ciphertext;
            }

            public byte[] Ciphertext { get; }

            public override string ToString()
            {
                return Ciphertext.Length.ToString();
            }
        }
#endif
    }
}
