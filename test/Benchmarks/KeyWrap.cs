using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Diagnosers;
using BenchmarkDotNet.Running;

namespace JsonWebToken.Performance
{
    [MemoryDiagnoser]
    public class KeyWrap
    {
        private readonly SymmetricJwk _key = SymmetricJwk.FromBase64Url("U1oK6e4BAR4kKTdyA1OqEFYwX9pIrswuUMNt8qW4z-k");
        private readonly SymmetricJwk _keyToWrap = SymmetricJwk.FromBase64Url("gXoKEcss-xFuZceE6B3VkEMLw-f0h9tGfyaheF5jqP8");
        private readonly byte[] wrappedKey;

        public KeyWrap()
        {
            AesKeyWrapper kwp = new AesKeyWrapper(_key, EncryptionAlgorithm.Aes128CbcHmacSha256, KeyManagementAlgorithm.Aes256KW);
            wrappedKey = new byte[kwp.GetKeyWrapSize()];
        }

        [Benchmark]
        public void Kw_Optimized()
        {

            AesKeyWrapper kwp = new AesKeyWrapper(_key, EncryptionAlgorithm.Aes128CbcHmacSha256, KeyManagementAlgorithm.Aes256KW);

            kwp.TryWrapKey(_keyToWrap, null, wrappedKey, out var cek, out var bytesWritten);
        }
    }

    [MemoryDiagnoser]
    public class KeyUnwrap
    {
        private readonly SymmetricJwk _key = SymmetricJwk.FromBase64Url("U1oK6e4BAR4kKTdyA1OqEFYwX9pIrswuUMNt8qW4z-k");
        private readonly SymmetricJwk _keyToWrap = SymmetricJwk.FromBase64Url("gXoKEcss-xFuZceE6B3VkEMLw-f0h9tGfyaheF5jqP8");
        private readonly byte[] wrappedKey;
        private readonly byte[] unwrappedKey;

        public KeyUnwrap()
        {
            AesKeyWrapper kwp = new AesKeyWrapper(_key, EncryptionAlgorithm.Aes128CbcHmacSha256, KeyManagementAlgorithm.Aes256KW);
            wrappedKey = new byte[kwp.GetKeyWrapSize()];
            kwp.TryWrapKey(_keyToWrap, null, wrappedKey, out var cek, out var bytesWritten);
            unwrappedKey = new byte[kwp.GetKeyUnwrapSize(wrappedKey.Length)];
        }

        [Benchmark]
        public void Kw_Optimized()
        {

            AesKeyWrapper kwp = new AesKeyWrapper(_key, EncryptionAlgorithm.Aes128CbcHmacSha256, KeyManagementAlgorithm.Aes256KW);
            var unwrapped = kwp.TryUnwrapKey(wrappedKey, unwrappedKey, null, out int keyWrappedBytesWritten);
        }
    }
}
