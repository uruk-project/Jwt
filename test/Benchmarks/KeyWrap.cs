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
            SymmetricKeyWrapProvider kwp = new SymmetricKeyWrapProvider(_key, KeyManagementAlgorithms.Aes256KW);
            wrappedKey = new byte[kwp.GetKeyWrapSize(ContentEncryptionAlgorithms.Aes128CbcHmacSha256)];
        }

        [Benchmark(Baseline = true)]
        public void KwOld()
        {
            SymmetricKeyWrapProviderOld kwp = new SymmetricKeyWrapProviderOld(_key, KeyManagementAlgorithms.Aes256KW);

            kwp.TryWrapKey(_keyToWrap.RawK, wrappedKey, out var bytesWritten);
        }

        [Benchmark]
        public void Kw_Optimized()
        {

            SymmetricKeyWrapProvider kwp = new SymmetricKeyWrapProvider(_key, KeyManagementAlgorithms.Aes256KW);

            kwp.TryWrapKey(_keyToWrap.RawK, wrappedKey, out var bytesWritten);
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
            SymmetricKeyWrapProvider kwp = new SymmetricKeyWrapProvider(_key, KeyManagementAlgorithms.Aes256KW);
            wrappedKey = new byte[kwp.GetKeyWrapSize(ContentEncryptionAlgorithms.Aes128CbcHmacSha256)];
            kwp.TryWrapKey(_keyToWrap.RawK, wrappedKey, out var bytesWritten);
            unwrappedKey = new byte[kwp.GetKeyUnwrapSize(wrappedKey.Length)];
        }

        [Benchmark(Baseline = true)]
        public void KwOld()
        {
            SymmetricKeyWrapProviderOld kwp = new SymmetricKeyWrapProviderOld(_key, KeyManagementAlgorithms.Aes256KW);
            var unwrapped = kwp.TryUnwrapKey(wrappedKey, unwrappedKey, out int keyWrappedBytesWritten);
        }

        [Benchmark]
        public void Kw_Optimized()
        {

            SymmetricKeyWrapProvider kwp = new SymmetricKeyWrapProvider(_key, KeyManagementAlgorithms.Aes256KW);
            var unwrapped = kwp.TryUnwrapKey(wrappedKey, unwrappedKey, out int keyWrappedBytesWritten);
        }
    }
}
