using JsonWebToken.Internal;

namespace JsonWebToken.Tests.Cryptography
{
#if SUPPORT_SIMD
    public class Aes192NiTests : Aes192Tests
    {
        protected override AesDecryptor CreateDecryptor()
            => System.Runtime.Intrinsics.X86.Aes.IsSupported ? (AesDecryptor)new Aes192CbcDecryptor() : new AesCbcDecryptor(EncryptionAlgorithm.Aes192CbcHmacSha384);

        protected override AesEncryptor CreateEncryptor()
            => System.Runtime.Intrinsics.X86.Aes.IsSupported ? (AesEncryptor)new Aes192CbcEncryptor() : new AesCbcEncryptor(EncryptionAlgorithm.Aes192CbcHmacSha384);
    }
#endif
}
