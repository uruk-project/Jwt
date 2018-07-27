using Xunit;
using System;

namespace JsonWebToken.Tests
{
    public class KwTests
    {
        private readonly SymmetricJwk _key = SymmetricJwk.FromBase64Url("U1oK6e4BAR4kKTdyA1OqEFYwX9pIrswuUMNt8qW4z-k");
        private readonly SymmetricJwk _keyToWrap = SymmetricJwk.FromBase64Url("gXoKEcss-xFuZceE6B3VkEMLw-f0h9tGfyaheF5jqP8");
        
        [Fact]
        public void WrapUnwrap()
        {
            var kwp = new SymmetricKeyWrapProvider(_key, KeyManagementAlgorithms.Aes256KW);
            byte[] wrappedKey = new byte[kwp.GetKeyWrapSize(ContentEncryptionAlgorithms.Aes128CbcHmacSha256)];

            var wrapped = kwp.TryWrapKey(_keyToWrap.RawK, wrappedKey, out var bytesWritten);
            Assert.True(wrapped);

            var unwrappedKey = new byte[kwp.GetKeyUnwrapSize(wrappedKey.Length)];
            var unwrapped = kwp.TryUnwrapKey(wrappedKey, unwrappedKey, out int keyWrappedBytesWritten);
            Assert.True(unwrapped);
        }
    }
}
