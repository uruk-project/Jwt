namespace JsonWebToken.Tests.Cryptography
{
#if SUPPORT_SIMD
    public class Aes192NiTests : Aes192Tests
    {
        private protected override AesDecryptor CreateDecryptor()
          => new Aes192CbcDecryptor();

        private protected override AesEncryptor CreateEncryptor()
            => new Aes192CbcEncryptor();
    }
#endif
}
