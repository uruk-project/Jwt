using System;
using JsonWebToken.Internal;

namespace JsonWebToken.Tests.Cryptography
{
#if NETCOREAPP3_0
    public class Aes192NiTests : Aes192Tests
    {
        protected override AesDecryptor CreateDecryptor(ReadOnlySpan<byte> key)
          => new AesNiCbc192Decryptor(key);

        protected override AesEncryptor CreateEncryptor(ReadOnlySpan<byte> key)
            => new AesNiCbc192Encryptor(key);
    }
#endif
}
