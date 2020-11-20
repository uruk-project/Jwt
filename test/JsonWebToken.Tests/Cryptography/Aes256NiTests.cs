using System;
using JsonWebToken.Cryptography;

namespace JsonWebToken.Tests.Cryptography
{
#if SUPPORT_SIMD
    public class Aes256NiTests : Aes256Tests
    {
        private protected override AesDecryptor CreateDecryptor()
          => new Aes256CbcDecryptor();

        private protected override AesEncryptor CreateEncryptor()
            => new Aes256CbcEncryptor();
    }
#endif
}
