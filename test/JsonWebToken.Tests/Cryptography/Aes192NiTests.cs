using JsonWebToken.Internal;

namespace JsonWebToken.Tests.Cryptography
{
#if NETCOREAPP3_0
    public class Aes192NiTests : Aes192Tests
    {
        protected override AesDecryptor CreateDecryptor()
          => new Aes192CbcDecryptor();

        protected override AesEncryptor CreateEncryptor()
            => new Aes192CbcEncryptor();
    }
#endif
}
