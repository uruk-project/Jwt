using System;
using Xunit;

namespace JsonWebToken.Tests.Cryptography
{
    // Test data set from https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/aes/AESAVS.pdf
    public abstract class AesTests
    {
        protected abstract AesEncryptor CreateEncryptor(ReadOnlySpan<byte> key);

        protected abstract AesDecryptor CreateDecryptor(ReadOnlySpan<byte> key);

        protected void VerifyGfsBoxKat(ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> expectedCiphertext, ReadOnlySpan<byte> key)
        {
            var iv = ByteUtils.HexToByteArray("00000000000000000000000000000000");
            var encryptor = CreateEncryptor(key);
            Span<byte> ciphertext = new byte[(plaintext.Length + 16) & ~15];
            encryptor.Encrypt(plaintext, iv, ciphertext);

            // The last 16 bytes are ignored as the test data sets are for ECB mode
            Assert.Equal(expectedCiphertext.ToArray(), ciphertext.Slice(0, ciphertext.Length - 16).ToArray());
        }

        protected void VerifyKeySboxKat(ReadOnlySpan<byte> key, ReadOnlySpan<byte> expectedCiphertext)
        {
            var iv = ByteUtils.HexToByteArray("00000000000000000000000000000000");
            var plaintext = ByteUtils.HexToByteArray("00000000000000000000000000000000");
            var encryptor = CreateEncryptor(key);
            Span<byte> ciphertext = new byte[(plaintext.Length + 16) & ~15];
            encryptor.Encrypt(plaintext, iv, ciphertext);

            // The last 16 bytes are ignored as the test data sets are for ECB mode
            Assert.Equal(expectedCiphertext.ToArray(), ciphertext.Slice(0, ciphertext.Length - 16).ToArray());
        }

        protected void VerifyVarTxtKat(ReadOnlySpan<byte> key, ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> iv, ReadOnlySpan<byte> expectedCiphertext)
        {
            var encryptor = CreateEncryptor(key);
            Span<byte> ciphertext = new byte[(plaintext.Length + 16) & ~15];
            encryptor.Encrypt(plaintext, iv, ciphertext);

            // The last 16 bytes are ignored as the test data sets are for ECB mode
            Assert.Equal(expectedCiphertext.ToArray(), ciphertext.Slice(0, ciphertext.Length - 16).ToArray());
        }
    }
}
