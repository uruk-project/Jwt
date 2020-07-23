using System;
using JsonWebToken.Internal;

namespace JsonWebToken.Tests.Cryptography
{
#if NETCOREAPP3_0

    public class Aes256NiTests : Aes256Tests
    {
        protected override AesDecryptor CreateDecryptor(ReadOnlySpan<byte> key)
          => new Aes256NiCbcDecryptor(key);

        protected override AesEncryptor CreateEncryptor(ReadOnlySpan<byte> key)
            => new Aes256NiCbcEncryptor();
    }
#endif
}
