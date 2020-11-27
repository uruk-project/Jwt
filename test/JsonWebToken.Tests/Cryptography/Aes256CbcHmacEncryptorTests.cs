using System;
using System.Text;
using Xunit;
using JsonWebToken.Cryptography;

namespace JsonWebToken.Tests
{
    public class Aes256CbcHmacEncryptorTests
    {
        [Fact]
        public void Encrypt_Decrypt()
        {
            var data = Encoding.UTF8.GetBytes("This is a test string for encryption.");
            var ciphertext = new Span<byte>(new byte[(data.Length + 16) & ~15]);
            var authenticationTag = new Span<byte>(new byte[64]);
            var plaintext = new Span<byte>(new byte[data.Length]);
            var key = SymmetricJwk.GenerateKey(512);
            var nonce = new byte[] { 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1 };
            var encryptor = new AesCbcHmacEncryptor(EncryptionAlgorithm.A256CbcHS512);
            encryptor.Encrypt(key.AsSpan(), data, nonce, nonce, ciphertext, authenticationTag, out int tagSize);
            var decryptor = new AesCbcHmacDecryptor(EncryptionAlgorithm.A256CbcHS512);
            bool decrypted = decryptor.TryDecrypt(key.K, ciphertext, nonce, nonce, authenticationTag.Slice(0, tagSize), plaintext, out int bytesWritten);
            Assert.True(decrypted);
            Assert.Equal(32, tagSize);
        }

        [Fact]
        public void EncryptFast_Decrypt()
        {
            var data = Encoding.UTF8.GetBytes("This is a test string for encryption.");
            var ciphertext = new Span<byte>(new byte[(data.Length + 16) & ~15]);
            var authenticationTag = new Span<byte>(new byte[64]);
            var plaintext = new Span<byte>(new byte[data.Length]);
            var key = SymmetricJwk.GenerateKey(512);
            var nonce = new byte[] { 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1 };
            var encryptor = new AesCbcHmacEncryptor(EncryptionAlgorithm.A256CbcHS512);
            encryptor.Encrypt(key.AsSpan(), data, nonce, nonce, ciphertext, authenticationTag, out int tagSize);
            var decryptor = new AesCbcHmacDecryptor(EncryptionAlgorithm.A256CbcHS512);
            bool decrypted = decryptor.TryDecrypt(key.K, ciphertext, nonce, nonce, authenticationTag.Slice(0, tagSize), plaintext, out int bytesWritten);
            Assert.True(decrypted);
            Assert.Equal(32, tagSize);
        }

#if SUPPORT_SIMD
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
                var authenticationTag = new Span<byte>(new byte[64]);
                var plaintext = new Span<byte>(new byte[ciphertext.Length]);
                var key = new SymmetricJwk(Encoding.UTF8.GetBytes("ThisIsA128bitKey" + "ThisIsA128bitKey" + "ThisIsA128bitKey" + "ThisIsA128bitKey"));
                var nonce = Encoding.UTF8.GetBytes("ThisIsAnInitVect");
                var encryptorNi = new AesCbcHmacEncryptor(EncryptionAlgorithm.Aes256CbcHmacSha512, new Aes256CbcEncryptor());
                encryptorNi.Encrypt(key.AsSpan(), data, nonce, nonce, ciphertext, authenticationTag, out int tagSize);
                var decryptor = new AesCbcHmacDecryptor(EncryptionAlgorithm.Aes256CbcHmacSha512);
                bool decrypted = decryptor.TryDecrypt(key.K, ciphertext, nonce, nonce, authenticationTag.Slice(0, tagSize), plaintext, out int bytesWritten);
                Assert.True(decrypted);
                Assert.Equal(data, plaintext.Slice(0, bytesWritten).ToArray());

                var decryptorNi = new AesCbcHmacDecryptor(EncryptionAlgorithm.Aes256CbcHmacSha512, new Aes256CbcDecryptor());
                plaintext.Clear();
                decrypted = decryptorNi.TryDecrypt(key.K, ciphertext, nonce, nonce, authenticationTag.Slice(0, tagSize), plaintext, out bytesWritten);
                Assert.True(decrypted);
                Assert.Equal(data, plaintext.Slice(0, bytesWritten).ToArray());
                Assert.Equal(32, tagSize);
            }
        }
#endif

        [Fact]
        public void Rfc7518_Encrypt()
        {
            var k = new byte[] {
               0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
               0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
               0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
               0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f };

            var p = new byte[] {
              0x41, 0x20, 0x63, 0x69, 0x70, 0x68, 0x65, 0x72, 0x20, 0x73, 0x79, 0x73, 0x74, 0x65, 0x6d, 0x20,
              0x6d, 0x75, 0x73, 0x74, 0x20, 0x6e, 0x6f, 0x74, 0x20, 0x62, 0x65, 0x20, 0x72, 0x65, 0x71, 0x75,
              0x69, 0x72, 0x65, 0x64, 0x20, 0x74, 0x6f, 0x20, 0x62, 0x65, 0x20, 0x73, 0x65, 0x63, 0x72, 0x65,
              0x74, 0x2c, 0x20, 0x61, 0x6e, 0x64, 0x20, 0x69, 0x74, 0x20, 0x6d, 0x75, 0x73, 0x74, 0x20, 0x62,
              0x65, 0x20, 0x61, 0x62, 0x6c, 0x65, 0x20, 0x74, 0x6f, 0x20, 0x66, 0x61, 0x6c, 0x6c, 0x20, 0x69,
              0x6e, 0x74, 0x6f, 0x20, 0x74, 0x68, 0x65, 0x20, 0x68, 0x61, 0x6e, 0x64, 0x73, 0x20, 0x6f, 0x66,
              0x20, 0x74, 0x68, 0x65, 0x20, 0x65, 0x6e, 0x65, 0x6d, 0x79, 0x20, 0x77, 0x69, 0x74, 0x68, 0x6f,
              0x75, 0x74, 0x20, 0x69, 0x6e, 0x63, 0x6f, 0x6e, 0x76, 0x65, 0x6e, 0x69, 0x65, 0x6e, 0x63, 0x65 };

            var iv = new byte[] { 0x1a, 0xf3, 0x8c, 0x2d, 0xc2, 0xb9, 0x6f, 0xfd, 0xd8, 0x66, 0x94, 0x09, 0x23, 0x41, 0xbc, 0x04 };

            var a = new byte[] {
                0x54, 0x68, 0x65, 0x20, 0x73, 0x65, 0x63, 0x6f, 0x6e, 0x64, 0x20, 0x70, 0x72, 0x69, 0x6e, 0x63,
                0x69, 0x70, 0x6c, 0x65, 0x20, 0x6f, 0x66, 0x20, 0x41, 0x75, 0x67, 0x75, 0x73, 0x74, 0x65, 0x20,
                0x4b, 0x65, 0x72, 0x63, 0x6b, 0x68, 0x6f, 0x66, 0x66, 0x73};

            var e = new byte[] {
              0x4a, 0xff, 0xaa, 0xad, 0xb7, 0x8c, 0x31, 0xc5, 0xda, 0x4b, 0x1b, 0x59, 0x0d, 0x10, 0xff, 0xbd,
              0x3d, 0xd8, 0xd5, 0xd3, 0x02, 0x42, 0x35, 0x26, 0x91, 0x2d, 0xa0, 0x37, 0xec, 0xbc, 0xc7, 0xbd,
              0x82, 0x2c, 0x30, 0x1d, 0xd6, 0x7c, 0x37, 0x3b, 0xcc, 0xb5, 0x84, 0xad, 0x3e, 0x92, 0x79, 0xc2,
              0xe6, 0xd1, 0x2a, 0x13, 0x74, 0xb7, 0x7f, 0x07, 0x75, 0x53, 0xdf, 0x82, 0x94, 0x10, 0x44, 0x6b,
              0x36, 0xeb, 0xd9, 0x70, 0x66, 0x29, 0x6a, 0xe6, 0x42, 0x7e, 0xa7, 0x5c, 0x2e, 0x08, 0x46, 0xa1,
              0x1a, 0x09, 0xcc, 0xf5, 0x37, 0x0d, 0xc8, 0x0b, 0xfe, 0xcb, 0xad, 0x28, 0xc7, 0x3f, 0x09, 0xb3,
              0xa3, 0xb7, 0x5e, 0x66, 0x2a, 0x25, 0x94, 0x41, 0x0a, 0xe4, 0x96, 0xb2, 0xe2, 0xe6, 0x60, 0x9e,
              0x31, 0xe6, 0xe0, 0x2c, 0xc8, 0x37, 0xf0, 0x53, 0xd2, 0x1f, 0x37, 0xff, 0x4f, 0x51, 0x95, 0x0b,
              0xbe, 0x26, 0x38, 0xd0, 0x9d, 0xd7, 0xa4, 0x93, 0x09, 0x30, 0x80, 0x6d, 0x07, 0x03, 0xb1, 0xf6 };

            var t = new byte[] {
               0X4d, 0xd3, 0xb4, 0xc0, 0x88, 0xa7, 0xf4, 0x5c, 0x21, 0x68, 0x39, 0x64, 0x5b, 0x20, 0x12, 0xbf,
               0X2e, 0x62, 0x69, 0xa8, 0xc5, 0x6a, 0x81, 0x6d, 0xbc, 0x1b, 0x26, 0x77, 0x61, 0x95, 0x5b, 0xc5 };

            var encryptor = new AesCbcHmacEncryptor(EncryptionAlgorithm.A256CbcHS512);

            var ciphertext = new byte[encryptor.GetCiphertextSize(p.Length)];
            var authenticationTag = new byte[encryptor.GetTagSize()];
            encryptor.Encrypt(k, p, iv, a, ciphertext, authenticationTag, out int tagSize);

            Assert.Equal(e, ciphertext);
            Assert.Equal(t, authenticationTag.AsSpan(0, tagSize).ToArray());
        }
    }
}