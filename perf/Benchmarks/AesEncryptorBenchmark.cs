using System.Text;
using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Diagnosers;
using JsonWebToken.Internal;

namespace JsonWebToken.Performance
{
    [MemoryDiagnoser]
    public class AesEncryptorBenchmark
    {
        private AesCbcHmacEncryptor? _encryptor;
#if NETCOREAPP3_0
        private AesCbcHmacEncryptor? _encryptorNi;
#endif
        private byte[]? data;
        private byte[]? ciphertext;
        private byte[]? authenticationTag;
        private byte[]? nonce;

        [GlobalSetup]
        public void Setup()
        {
            data = Encoding.UTF8.GetBytes("This is a test string for encryption.This is a test string for encryption.This is a test string for encryption.This is a test string for encryption.");
            ciphertext = (new byte[(data.Length + 16) & ~15]);
            authenticationTag = (new byte[32]);
            var key = SymmetricJwk.GenerateKey(256);
            nonce = new byte[] { 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1 };
            _encryptor = new AesCbcHmacEncryptor(key, EncryptionAlgorithm.Aes128CbcHmacSha256);
#if NETCOREAPP3_0
            _encryptorNi = new AesCbcHmacEncryptor(key.K.Slice(0, 16), EncryptionAlgorithm.Aes128CbcHmacSha256, new AesNiCbc128Encryptor(key.K.Slice(16)));
#endif  
        }

        [Benchmark(Baseline = true)]
        public void Encrypt()
        {

            _encryptor!.Encrypt(data, nonce, nonce, ciphertext, authenticationTag);
        }

#if NETCOREAPP3_0
        [Benchmark(Baseline = false)]
        public void Encrypt_Simd1()
        {
            _encryptorNi!.Encrypt(data, nonce, nonce, ciphertext, authenticationTag);
        }
#endif
    }
}
