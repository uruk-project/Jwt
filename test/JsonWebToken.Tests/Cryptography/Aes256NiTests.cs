using System;
using JsonWebToken.Internal;

namespace JsonWebToken.Tests.Cryptography
{
#if SUPPORT_SIMD
    public class Aes256NiTests : Aes256Tests
    {
        protected override AesDecryptor CreateDecryptor()
          => new Aes256CbcDecryptor();

        protected override AesEncryptor CreateEncryptor()
            => new Aes256CbcEncryptor();
    }
#endif
}
