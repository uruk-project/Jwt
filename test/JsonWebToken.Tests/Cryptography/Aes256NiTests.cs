using System;
using JsonWebToken.Cryptography;

namespace JsonWebToken.Tests.Cryptography
{
#if SUPPORT_SIMD
    public class Aes256NiTests : Aes256Tests
    {
        private protected override AesDecryptor CreateDecryptor()
             => System.Runtime.Intrinsics.X86.Aes.IsSupported? (AesDecryptor) new Aes256CbcDecryptor() : new AesCbcDecryptor(EncryptionAlgorithm.Aes256CbcHmacSha512);

        private protected override AesEncryptor CreateEncryptor()
            => System.Runtime.Intrinsics.X86.Aes.IsSupported ? (AesEncryptor)new Aes256CbcEncryptor() : new AesCbcEncryptor(EncryptionAlgorithm.Aes256CbcHmacSha512);
    }
#endif
}
