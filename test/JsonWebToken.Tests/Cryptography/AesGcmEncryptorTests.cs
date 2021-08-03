using System;
using System.Text;
using Xunit;
using JsonWebToken.Cryptography;

namespace JsonWebToken.Tests
{
#if SUPPORT_AESGCM
    public class AesGcmEncryptorTests
    {
        [Fact]
        public void Encrypt_Decrypt()
        {
            var data = Encoding.UTF8.GetBytes("This is a test string for encryption.");
            var ciphertext = new Span<byte>(new byte[data.Length]);
            var authenticationTag = new Span<byte>(new byte[16]);
            var plaintext = new Span<byte>(new byte[data.Length]);
            var key = SymmetricJwk.GenerateKey(EncryptionAlgorithm.A128Gcm);
            var nonce = new byte[] { 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1 };
            var encryptor = new AesGcmEncryptor(EncryptionAlgorithm.A128Gcm);
            encryptor.Encrypt(key.AsSpan(), data, nonce, nonce, ciphertext, authenticationTag, out int tagSize);
            var decryptor = new AesGcmDecryptor(EncryptionAlgorithm.A128Gcm);
            bool decrypted = decryptor.TryDecrypt(key.K, ciphertext, nonce, nonce, authenticationTag.Slice(0, tagSize), plaintext, out int bytesWritten);
            Assert.True(decrypted);
            Assert.Equal(16, tagSize);
            Assert.Equal(plaintext.Length, bytesWritten);
        }

        [Fact]
        public void EncryptFast_Decrypt()
        {
            var data = Encoding.UTF8.GetBytes("This is a test string for encryption.");
            var ciphertext = new Span<byte>(new byte[data.Length]);
            var authenticationTag = new Span<byte>(new byte[16]);
            var plaintext = new Span<byte>(new byte[data.Length]);
            var key = SymmetricJwk.GenerateKey(EncryptionAlgorithm.A128Gcm);
            var nonce = new byte[] { 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1 };
            var encryptor = new AesGcmEncryptor(EncryptionAlgorithm.A128Gcm);
            encryptor.Encrypt(key.AsSpan(), data, nonce, nonce, ciphertext, authenticationTag, out int tagSize);
            var decryptor = new AesGcmDecryptor(EncryptionAlgorithm.A128Gcm);
            bool decrypted = decryptor.TryDecrypt(key.K, ciphertext, nonce, nonce, authenticationTag.Slice(0, tagSize), plaintext, out int bytesWritten);
            Assert.True(decrypted);
            Assert.Equal(16, tagSize);
            Assert.Equal(plaintext.Length, bytesWritten);
        }

        [Theory]
        [InlineData("")]
        [InlineData("1")]
        [InlineData("This is a test string for encryption.")]
        [InlineData("This is a test string for encryption.0")]
        [InlineData("This is a test string for encryption.01")]
        [InlineData("This is a test string for encryption.012")]
        [InlineData("This is a test string for encryption.0123")]
        [InlineData("This is a test string for encryption.01234")]
        [InlineData("This is a test string for encryption.012345")]
        [InlineData("This is a test string for encryption.0123456")]
        [InlineData("This is a test string for encryption.01234567")]
        [InlineData("This is a test string for encryption.012345678")]
        [InlineData("This is a test string for encryption.0123456789")]
        [InlineData("This is a test string for encryption.01234567890")]
        [InlineData("This is a test string for encryption.012345678901")]
        [InlineData("This is a test string for encryption.0123456789012")]
        [InlineData("This is a test string for encryption.01234567890123")]
        [InlineData("This is a test string for encryption.012345678901234")]
        [InlineData("This is a test string for encryption.This is a test string for encryption.This is a test string for encryption.This is a test string for encryption.")]
        public void EncryptSimd_Decrypt(string value)
        {
            if (System.Runtime.Intrinsics.X86.Aes.IsSupported)
            {
                var data = Encoding.UTF8.GetBytes(value);
                var ciphertext = new Span<byte>(new byte[(data.Length + 16) & ~15]);
                var authenticationTag = new Span<byte>(new byte[32]);
                var plaintext = new Span<byte>(new byte[ciphertext.Length]);
                var key = SymmetricJwk.FromByteArray(Encoding.UTF8.GetBytes("ThisIsA128bitKey" + "ThisIsA128bitKey"));
                var nonce = Encoding.UTF8.GetBytes("ThisIsAnInitVect");
                var encryptorNi = new AesCbcHmacEncryptor(EncryptionAlgorithm.A128CbcHS256, new Aes128CbcEncryptor());
                encryptorNi.Encrypt(key.K, data, nonce, nonce, ciphertext, authenticationTag, out int tagSize);
                var decryptor = new AesCbcHmacDecryptor(EncryptionAlgorithm.A128CbcHS256);
                bool decrypted = decryptor.TryDecrypt(key.K, ciphertext, nonce, nonce, authenticationTag.Slice(0, tagSize), plaintext, out int bytesWritten);
                Assert.True(decrypted, "decrypted");
                Assert.Equal(data, plaintext.Slice(0, bytesWritten).ToArray());
                Assert.Equal(16, tagSize);
            }
        }

        [Fact]
        public void Decrypt_Empty()
        {
            Span<byte> data = default;
            Span<byte> authenticationTag = default;
            var plaintext = new byte[0];
            var key = SymmetricJwk.FromByteArray(Encoding.UTF8.GetBytes("ThisIsA128bitKey" + "ThisIsA128bitKey"));
            Span<byte> nonce = default;
            Span<byte> associatedData = default;
            var decryptor = new AesCbcHmacDecryptor(EncryptionAlgorithm.A128CbcHS256);

            bool decrypted = decryptor.TryDecrypt(key.K, data, nonce, associatedData, authenticationTag, plaintext, out int bytesWritten);
            Assert.False(decrypted);
            Assert.Equal(0, bytesWritten);
        }
    }
#endif
}