using JsonWebToken.Cryptography;

namespace JsonWebToken.Tests.Cryptography
{
#if SUPPORT_SIMD
    public class Aes192NiTests : Aes192Tests
    {
        private protected override AesDecryptor CreateDecryptor()
            => System.Runtime.Intrinsics.X86.Aes.IsSupported ? (AesDecryptor)new Aes192CbcDecryptor() : new AesCbcDecryptor(EncryptionAlgorithm.A192CbcHS384);

        private protected override AesEncryptor CreateEncryptor()
            => System.Runtime.Intrinsics.X86.Aes.IsSupported ? (AesEncryptor)new Aes192CbcEncryptor() : new AesCbcEncryptor(EncryptionAlgorithm.A192CbcHS384);
    }
#endif
}
