using System;
using JsonWebToken.Internal;

namespace JsonWebToken.Tests.Cryptography
{
#if NETCOREAPP3_0
    public class Aes128NiTests : Aes128Tests
    {
        protected override AesDecryptor CreateDecryptor(ReadOnlySpan<byte> key)
          => new Aes128NiCbcDecryptor(key);

        protected override AesEncryptor CreateEncryptor(ReadOnlySpan<byte> key)
            => new Aes128NiCbcEncryptor(key);
    }
#endif
}
