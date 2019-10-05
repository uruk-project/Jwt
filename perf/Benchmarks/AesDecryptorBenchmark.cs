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
        private AesCbcHmacDecryptor? _decryptor;
#if NETCOREAPP3_0
        private AesCbcHmacDecryptor? _decryptorNi;
#endif
        private byte[]? plaintext;
        private byte[]? ciphertext;
        private byte[]? authenticationTag;
        private byte[]? nonce;

        [GlobalSetup]
        public void Setup()
        {
            plaintext = Encoding.UTF8.GetBytes("This is a test string for encryption.This is a test string for encryption.This is a test string for encryption.This is a test string for encryption.");
            ciphertext = (new byte[(plaintext.Length + 16) & ~15]);
            authenticationTag = (new byte[32]);
            var key = SymmetricJwk.GenerateKey(256);
            nonce = new byte[] { 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1 };
            var encryptor = new AesCbcHmacEncryptor(key.K.Slice(16), EncryptionAlgorithm.Aes128CbcHmacSha256, new AesCbcEncryptor(key.K.Slice(0, 16), EncryptionAlgorithm.Aes128CbcHmacSha256));
            encryptor.Encrypt(plaintext, nonce, nonce, ciphertext, authenticationTag);
            _decryptor = new AesCbcHmacDecryptor(key, EncryptionAlgorithm.Aes128CbcHmacSha256);
            plaintext.AsSpan().Clear();
#if NETCOREAPP3_0
            _decryptorNi = new AesCbcHmacDecryptor(key.K.Slice(16), EncryptionAlgorithm.Aes128CbcHmacSha256, new AesNiCbc128Decryptor(key.K.Slice(16)));
#endif
        }

        [Benchmark(Baseline = true)]
        public void Decrypt()
        {
            _decryptor!.TryDecrypt(ciphertext, nonce, nonce, authenticationTag, plaintext, out int bytesWritten);
        }

#if NETCOREAPP3_0
        [Benchmark(Baseline = false)]
        public void Decrypt_Simd1()
        {
            _decryptorNi!.TryDecrypt(ciphertext, nonce, nonce, authenticationTag, plaintext, out int bytesWritten);
        }
#endif
    }
}
