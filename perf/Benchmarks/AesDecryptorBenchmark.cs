using System;
using System.Text;
using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Diagnosers;
using JsonWebToken.Internal;

namespace JsonWebToken.Performance
{
    [MemoryDiagnoser]
    public class AesDecryptorBenchmark
    {
        private AesCbcHmacEncryptor? _decryptor;
#if NETCOREAPP3_0
        private Aes128CbcHmac256Encryptor? _decryptorNi;
#endif
        private byte[]? plaintext;
        private byte[]? ciphertext;
        private byte[]? authenticationTag;
        private byte[]? nonce;

        [GlobalSetup]
        public void Setup()
        {
            plaintext = Encoding.UTF8.GetBytes("This is a test string for encryption.");
            ciphertext = (new byte[(plaintext.Length + 16) & ~15]);
            authenticationTag = (new byte[32]);
            var key = SymmetricJwk.GenerateKey(256);
            nonce = new byte[] { 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1 };
            _decryptor = new AesCbcHmacEncryptor(key, EncryptionAlgorithm.Aes128CbcHmacSha256);
            _decryptor.Encrypt(plaintext, nonce, nonce, ciphertext, authenticationTag);
            plaintext.AsSpan().Clear();
#if NETCOREAPP3_0
            _decryptorNi = new Aes128CbcHmac256Encryptor(key);
#endif
        }

        [Benchmark(Baseline = true)]
        public void Decrypt_Old()
        {
            _decryptor!.TryDecrypt(ciphertext, nonce, nonce, authenticationTag, plaintext, out int bytesWritten);
        }

        [Benchmark(Baseline = false)]
        public void Decrypt_NoStream()
        {
            _decryptor!.TryDecryptNoStream(ciphertext, nonce, nonce, authenticationTag, plaintext, out int bytesWritten);
        }
#if NETCOREAPP3_0
        [Benchmark(Baseline = false)]
        public void Encrypt_Simd1()
        {
            _decryptorNi!.TryDecrypt(ciphertext, nonce, nonce, authenticationTag, plaintext, out int bytesWritten);
        }  
#endif
    }
}
