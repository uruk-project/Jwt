using System;
using JsonWebToken.Internal;

namespace JsonWebToken.Tests.Cryptography
{
#if NETCOREAPP3_0
    public class Aes192NiTests : Aes192Tests
    {
        protected override AesDecryptor CreateDecryptor(ReadOnlySpan<byte> key)
          => new Aes192NiCbcDecryptor(key);

        protected override AesEncryptor CreateEncryptor(ReadOnlySpan<byte> key)
            => new Aes192NiCbcEncryptor();
    }
#endif
}
