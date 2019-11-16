using System;
using JsonWebToken.Internal;

namespace JsonWebToken.Tests.Cryptography
{
#if NETCOREAPP3_0
    public class Aes128NiTests : Aes128Tests
    {
        protected override AesDecryptor CreateDecryptor(ReadOnlySpan<byte> key)
          => new AesNiCbc128Decryptor(key);

        protected override AesEncryptor CreateEncryptor(ReadOnlySpan<byte> key)
            => new AesNiCbc128Encryptor(key);
    }
#endif
}
