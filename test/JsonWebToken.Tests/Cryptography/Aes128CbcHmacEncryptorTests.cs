using System;
using System.Text;
using Xunit;
using JsonWebToken.Cryptography;

namespace JsonWebToken.Tests
{
    public class Aes128CbcHmacEncryptorTests
    {
        [Fact]
        public void Encrypt_Decrypt()
        {
            var data = Encoding.UTF8.GetBytes("This is a test string for encryption.");
            var ciphertext = new Span<byte>(new byte[(data.Length + 16) & ~15]);
            var authenticationTag = new Span<byte>(new byte[32]);
            var plaintext = new Span<byte>(new byte[data.Length]);
            var key = SymmetricJwk.GenerateKey(256);
            var nonce = new byte[] { 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1 };
            var encryptor = new AesCbcHmacEncryptor(EncryptionAlgorithm.A128CbcHS256, new AesCbcEncryptor(EncryptionAlgorithm.A128CbcHS256));
            encryptor.Encrypt(key.AsSpan(), data, nonce, nonce, ciphertext, authenticationTag, out int tagSize);
            var decryptor = new AesCbcHmacDecryptor(EncryptionAlgorithm.A128CbcHS256);
            bool decrypted = decryptor.TryDecrypt(key.K, ciphertext, nonce, nonce, authenticationTag.Slice(0, tagSize), plaintext, out int bytesWritten);
            Assert.True(decrypted);
            Assert.Equal(16, tagSize);
        }

        [Fact]
        public void EncryptFast_Decrypt()
        {
            var data = Encoding.UTF8.GetBytes("This is a test string for encryption.");
            var ciphertext = new Span<byte>(new byte[(data.Length + 16) & ~15]);
            var authenticationTag = new Span<byte>(new byte[32]);
            var plaintext = new Span<byte>(new byte[data.Length]);
            var key = SymmetricJwk.GenerateKey(256);
            var nonce = new byte[] { 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1 };
            var encryptor = new AesCbcHmacEncryptor(EncryptionAlgorithm.A128CbcHS256, new AesCbcEncryptor(EncryptionAlgorithm.A128CbcHS256));
            encryptor.Encrypt(key.AsSpan(), data, nonce, nonce, ciphertext, authenticationTag, out int tagSize);
            var decryptor = new AesCbcHmacDecryptor(EncryptionAlgorithm.A128CbcHS256);
            bool decrypted = decryptor.TryDecrypt(key.K, ciphertext, nonce, nonce, authenticationTag.Slice(0, tagSize), plaintext, out int bytesWritten);
            Assert.True(decrypted);
            Assert.Equal(16, tagSize);
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

            var decryptorNi = new AesCbcHmacDecryptor(EncryptionAlgorithm.A128CbcHS256, new Aes128CbcDecryptor());
            plaintext.Clear();
            decrypted = decryptorNi.TryDecrypt(key.K, ciphertext, nonce, nonce, authenticationTag.Slice(0, tagSize), plaintext, out bytesWritten);
            Assert.True(decrypted, "decrypted NI");
            Assert.Equal(data, plaintext.Slice(0, bytesWritten).ToArray());
            Assert.Equal(16, tagSize);
        }
#endif

        [Fact]
        public void Rfc7518_Encrypt()
        {
            var k = new byte[] {
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f };

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
                0xc8, 0x0e, 0xdf, 0xa3, 0x2d, 0xdf, 0x39, 0xd5, 0xef, 0x00, 0xc0, 0xb4, 0x68, 0x83, 0x42, 0x79,
                0xa2, 0xe4, 0x6a, 0x1b, 0x80, 0x49, 0xf7, 0x92, 0xf7, 0x6b, 0xfe, 0x54, 0xb9, 0x03, 0xa9, 0xc9,
                0xa9, 0x4a, 0xc9, 0xb4, 0x7a, 0xd2, 0x65, 0x5c, 0x5f, 0x10, 0xf9, 0xae, 0xf7, 0x14, 0x27, 0xe2,
                0xfc, 0x6f, 0x9b, 0x3f, 0x39, 0x9a, 0x22, 0x14, 0x89, 0xf1, 0x63, 0x62, 0xc7, 0x03, 0x23, 0x36,
                0x09, 0xd4, 0x5a, 0xc6, 0x98, 0x64, 0xe3, 0x32, 0x1c, 0xf8, 0x29, 0x35, 0xac, 0x40, 0x96, 0xc8,
                0x6e, 0x13, 0x33, 0x14, 0xc5, 0x40, 0x19, 0xe8, 0xca, 0x79, 0x80, 0xdf, 0xa4, 0xb9, 0xcf, 0x1b,
                0x38, 0x4c, 0x48, 0x6f, 0x3a, 0x54, 0xc5, 0x10, 0x78, 0x15, 0x8e, 0xe5, 0xd7, 0x9d, 0xe5, 0x9f,
                0xbd, 0x34, 0xd8, 0x48, 0xb3, 0xd6, 0x95, 0x50, 0xa6, 0x76, 0x46, 0x34, 0x44, 0x27, 0xad, 0xe5,
                0x4b, 0x88, 0x51, 0xff, 0xb5, 0x98, 0xf7, 0xf8, 0x00, 0x74, 0xb9, 0x47, 0x3c, 0x82, 0xe2, 0xdb };

            var t = new byte[] { 0x65, 0x2c, 0x3f, 0xa3, 0x6b, 0x0a, 0x7c, 0x5b, 0x32, 0x19, 0xfa, 0xb3, 0xa3, 0x0b, 0xc1, 0xc4 };

            var encryptor = new AesCbcHmacEncryptor(EncryptionAlgorithm.A128CbcHS256, new AesCbcEncryptor(EncryptionAlgorithm.A128CbcHS256));

            var ciphertext = new byte[encryptor.GetCiphertextSize(p.Length)];
            var authenticationTag = new byte[encryptor.GetTagSize()];
            encryptor.Encrypt(k, p, iv, a, ciphertext, authenticationTag, out int tagSize);

            Assert.Equal(e, ciphertext);
            Assert.Equal(t, authenticationTag.AsSpan(0, tagSize).ToArray());
        }

        [Fact]
        public void Rfc7516_Decrypt()
        {
            Jwk encryptionKey = SymmetricJwk.FromBase64Url("GawgguFyGrWKav7AX4VKUg");
            string token = "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ.AxY8DCtDaGlsbGljb3RoZQ.KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY.U0m_YmjN04DJvceFICbCVQ";

            var policy = new TokenValidationPolicyBuilder()
                .WithDecryptionKey(encryptionKey)
                .IgnoreSignatureByDefault()
                .Build();

            var result = Jwt.TryParse(token, policy, out var jwt);

            Assert.True(result);
            Assert.Equal("Live long and prosper.", jwt.Plaintext);
            jwt.Dispose();
        }
    }
}