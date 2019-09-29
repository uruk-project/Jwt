using System;
using System.Text;
using JsonWebToken.Internal;
using Xunit;

namespace JsonWebToken.Tests
{
    public class AesCbcHmacEncryptorTests
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
            var encryptor = new AesCbcHmacEncryptor(key, EncryptionAlgorithm.Aes128CbcHmacSha256);
            encryptor.Encrypt(data, nonce, nonce, ciphertext, authenticationTag);
            bool decrypted = encryptor.TryDecrypt(ciphertext, nonce, nonce, authenticationTag, plaintext, out int bytesWritten);
            Assert.True(decrypted);
        }
#if NETCOREAPP3_0
        [Fact]
        public void EncryptFast_Decrypt()
        {
            var data = Encoding.UTF8.GetBytes("This is a test string for encryption.");
            var ciphertext = new Span<byte>(new byte[(data.Length + 16) & ~15]);
            var authenticationTag = new Span<byte>(new byte[32]);
            var ciphertext2 = new Span<byte>(new byte[(data.Length + 16) & ~15]);
            var authenticationTag2 = new Span<byte>(new byte[32]);
            var plaintext = new Span<byte>(new byte[data.Length]);
            var key = SymmetricJwk.GenerateKey(256);
            var nonce = new byte[] { 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1 };
            var encryptor = new AesCbcHmacEncryptor(key, EncryptionAlgorithm.Aes128CbcHmacSha256);
            encryptor.Encrypt(data, nonce, nonce, ciphertext, authenticationTag);
            encryptor.EncryptNoStream(data, nonce, nonce, ciphertext2, authenticationTag2);
            bool decrypted = encryptor.TryDecrypt(ciphertext2, nonce, nonce, authenticationTag2, plaintext, out int bytesWritten);
            Assert.True(decrypted);
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
        public void EncryptSimd_Decrypt(string value)
        {
            var data = Encoding.UTF8.GetBytes(value);
            var ciphertext = new Span<byte>(new byte[(data.Length + 16) & ~15]);
            var authenticationTag = new Span<byte>(new byte[32]);
            var plaintext = new Span<byte>(new byte[ciphertext.Length]);
            var key = new SymmetricJwk(Encoding.UTF8.GetBytes("ThisIsA128bitKey" + "ThisIsA128bitKey"));
            var nonce = Encoding.UTF8.GetBytes("ThisIsAnInitVect");
            var encryptor = new AesCbcHmacEncryptor(key, EncryptionAlgorithm.Aes128CbcHmacSha256);
            var encryptorNi = new Aes128CbcHmac256Encryptor(key);
            encryptorNi.Encrypt(data, nonce, nonce, ciphertext, authenticationTag);
            bool decrypted = encryptor.TryDecrypt(ciphertext, nonce, nonce, authenticationTag, plaintext, out int bytesWritten);
            Assert.True(decrypted);
            Assert.Equal(data, plaintext.Slice(0, bytesWritten).ToArray());

            plaintext.Clear();
            decrypted = encryptorNi.TryDecrypt(ciphertext, nonce, nonce, authenticationTag, plaintext, out bytesWritten);
            Assert.True(decrypted);
            Assert.Equal(data, plaintext.Slice(0, bytesWritten).ToArray());
        }
#endif
    }
}