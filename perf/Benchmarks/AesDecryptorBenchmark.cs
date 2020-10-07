using System.Collections.Generic;
using System.Linq;
using System.Text;
using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Diagnosers;
using JsonWebToken.Internal;

namespace JsonWebToken.Performance
{

    [MemoryDiagnoser]
    public class JwtDocumentBenchmark
    {
        private static readonly TokenValidationPolicy _policy = new TokenValidationPolicyBuilder().WithDecryptionKeys(Tokens.EncryptionKey).RequireSignature(Tokens.SigningKey).Build();

        [Benchmark(Baseline = false)]
        [ArgumentsSource(nameof(GetData))]
        public JwtDocument? TryParse(byte[] data)
        {
            JwtDocument.TryParse(data, _policy, out var document);
            document.Dispose();
            return document;
        }

        [Benchmark(Baseline = true)]
        [ArgumentsSource(nameof(GetData))]
        public Jwt? TryReadToken(byte[] data)
        {
            var reader = new JwtReader(Tokens.EncryptionKey);
            var document = reader.TryReadToken(data, _policy);
            return document.Token;
        }

        public static IEnumerable<byte[]> GetData()
        {
            yield return Encoding.UTF8.GetBytes(Tokens.ValidTokens["JWS 6 claims"]);
            yield return Encoding.UTF8.GetBytes(Tokens.ValidTokens["JWS 36 claims"]);
            yield return Encoding.UTF8.GetBytes(Tokens.ValidTokens["JWE 6 claims"]);
            yield return Encoding.UTF8.GetBytes(Tokens.ValidTokens["JWE 36 claims"]);
        }
    }

    [MemoryDiagnoser]
    public class AesDecryptorBenchmark
    {
        private readonly static AesCbcEncryptor _encryptor;
        private readonly static AesCbcDecryptor _decryptor;
#if SUPPORT_SIMD
        private readonly static Aes128CbcDecryptor _decryptorNi;
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
            _decryptor = new AesCbcDecryptor(EncryptionAlgorithm.Aes128CbcHmacSha256);
#if SUPPORT_SIMD
            _decryptorNi = new Aes128CbcDecryptor();
#endif
        }

        [Benchmark(Baseline = true)]
        [ArgumentsSource(nameof(GetData))]
        public bool Decrypt(Item data)
        {
            return _decryptor.TryDecrypt(key, data.Ciphertext, nonce, plaintext, out int bytesWritten);
        }

        public static IEnumerable<Item> GetData()
        {
            yield return new Item(GetCiphertext(Encoding.UTF8.GetBytes(Enumerable.Repeat('a', 1).ToArray())));
            yield return new Item(GetCiphertext(Encoding.UTF8.GetBytes(Enumerable.Repeat('a', 2048).ToArray())));
            yield return new Item(GetCiphertext(Encoding.UTF8.GetBytes(Enumerable.Repeat('a', 2048 * 16).ToArray())));
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

        private static byte[] GetCiphertext(byte[] plaintext)
        {
            var ciphertext = (new byte[(plaintext.Length + 16) & ~15]);

            _encryptor.Encrypt(key, plaintext, nonce, ciphertext);
            return ciphertext;
        }

#if SUPPORT_SIMD
        [Benchmark(Baseline = false)]
        [ArgumentsSource(nameof(GetData))]
        public bool Decrypt_Simd(Item data)
        {
            return _decryptorNi.TryDecrypt(key, data.Ciphertext, nonce, plaintext, out int bytesWritten);
        }
#endif
    }
}
