using System;
using System.Text;
using JsonWebToken.Internal;
using Xunit;

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
            var encryptor = new AesCbcHmacEncryptor(key, EncryptionAlgorithm.Aes128CbcHmacSha256);
            encryptor.Encrypt(data, nonce, nonce, ciphertext, authenticationTag);
            var decryptor = new AesCbcHmacDecryptor(key, EncryptionAlgorithm.Aes128CbcHmacSha256);
            bool decrypted = decryptor.TryDecrypt(ciphertext, nonce, nonce, authenticationTag, plaintext, out int bytesWritten);
            Assert.True(decrypted);
        }
#if NETCOREAPP3_0
        [Fact]
        public void EncryptFast_Decrypt()
        {
            var data = Encoding.UTF8.GetBytes("This is a test string for encryption.");
            var ciphertext = new Span<byte>(new byte[(data.Length + 16) & ~15]);
            var authenticationTag = new Span<byte>(new byte[32]);
            var plaintext = new Span<byte>(new byte[data.Length]);
            var key = SymmetricJwk.GenerateKey(256);
            var nonce = new byte[] { 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1 };
            var encryptor = new AesCbcHmacEncryptor(key, EncryptionAlgorithm.Aes128CbcHmacSha256);
            encryptor.Encrypt(data, nonce, nonce, ciphertext, authenticationTag);
            var decryptor = new AesCbcHmacDecryptor(key, EncryptionAlgorithm.Aes128CbcHmacSha256);
            bool decrypted = decryptor.TryDecrypt(ciphertext, nonce, nonce, authenticationTag, plaintext, out int bytesWritten);
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
        [InlineData("This is a test string for encryption.This is a test string for encryption.This is a test string for encryption.This is a test string for encryption.")]
        public void EncryptSimd_Decrypt(string value)
        {
            var data = Encoding.UTF8.GetBytes(value);
            var ciphertext = new Span<byte>(new byte[(data.Length + 16) & ~15]);
            var authenticationTag = new Span<byte>(new byte[32]);
            var plaintext = new Span<byte>(new byte[ciphertext.Length]);
            var key = new SymmetricJwk(Encoding.UTF8.GetBytes("ThisIsA128bitKey" + "ThisIsA128bitKey"));
            var nonce = Encoding.UTF8.GetBytes("ThisIsAnInitVect");
            var encryptorNi = new AesCbcHmacEncryptor(key.K.Slice(0, 16), EncryptionAlgorithm.Aes128CbcHmacSha256, new AesNiCbc128Encryptor(key.K.Slice(16)));
            encryptorNi.Encrypt(data, nonce, nonce, ciphertext, authenticationTag);
            var decryptorNi = new AesCbcHmacDecryptor(key.K.Slice(0, 16), EncryptionAlgorithm.Aes128CbcHmacSha256, new AesNiCbc128Decryptor(key.K.Slice(16)));
            bool decrypted = decryptorNi.TryDecrypt(ciphertext, nonce, nonce, authenticationTag, plaintext, out int bytesWritten);
            Assert.True(decrypted);
            Assert.Equal(data, plaintext.Slice(0, bytesWritten).ToArray());

            plaintext.Clear();
            decrypted = decryptorNi.TryDecrypt(ciphertext, nonce, nonce, authenticationTag, plaintext, out bytesWritten);
            Assert.True(decrypted);
            Assert.Equal(data, plaintext.Slice(0, bytesWritten).ToArray());
        }
#endif
    }

    public class Aes192CbcHmacEncryptorTests
    {
        [Fact]
        public void Encrypt_Decrypt()
        {
            var data = Encoding.UTF8.GetBytes("This is a test string for encryption.");
            var ciphertext = new Span<byte>(new byte[(data.Length + 16) & ~15]);
            var authenticationTag = new Span<byte>(new byte[48]);
            var plaintext = new Span<byte>(new byte[data.Length]);
            var key = SymmetricJwk.GenerateKey(386);
            var nonce = new byte[] { 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1 };
            var encryptor = new AesCbcHmacEncryptor(key, EncryptionAlgorithm.Aes192CbcHmacSha384);
            encryptor.Encrypt(data, nonce, nonce, ciphertext, authenticationTag);
            var decryptor = new AesCbcHmacDecryptor(key, EncryptionAlgorithm.Aes192CbcHmacSha384);
            bool decrypted = decryptor.TryDecrypt(ciphertext, nonce, nonce, authenticationTag, plaintext, out int bytesWritten);
            Assert.True(decrypted);
        }
#if NETCOREAPP3_0
        [Fact]
        public void EncryptFast_Decrypt()
        {
            var data = Encoding.UTF8.GetBytes("This is a test string for encryption.");
            var ciphertext = new Span<byte>(new byte[(data.Length + 16) & ~15]);
            var authenticationTag = new Span<byte>(new byte[48]);
            var plaintext = new Span<byte>(new byte[data.Length]);
            var key = SymmetricJwk.GenerateKey(386);
            var nonce = new byte[] { 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1 };
            var encryptor = new AesCbcHmacEncryptor(key, EncryptionAlgorithm.Aes192CbcHmacSha384);
            encryptor.Encrypt(data, nonce, nonce, ciphertext, authenticationTag);
            var decryptor = new AesCbcHmacDecryptor(key, EncryptionAlgorithm.Aes192CbcHmacSha384);
            bool decrypted = decryptor.TryDecrypt(ciphertext, nonce, nonce, authenticationTag, plaintext, out int bytesWritten);
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
        [InlineData("This is a test string for encryption.This is a test string for encryption.This is a test string for encryption.This is a test string for encryption.")]
        public void EncryptSimd_Decrypt(string value)
        {
            var data = Encoding.UTF8.GetBytes(value);
            var ciphertext = new Span<byte>(new byte[(data.Length + 16) & ~15]);
            var authenticationTag = new Span<byte>(new byte[48]);
            var plaintext = new Span<byte>(new byte[ciphertext.Length]);
            var key = new SymmetricJwk(Encoding.UTF8.GetBytes("ThisIsA128bitKey" + "ThisIsA128bitKey" + "ThisIsA128bitKey"));
            var nonce = Encoding.UTF8.GetBytes("ThisIsAnInitVect");
            var encryptorNi = new AesCbcHmacEncryptor(key.K.Slice(0, 24), EncryptionAlgorithm.Aes192CbcHmacSha384, new AesNiCbc192Encryptor(key.K.Slice(24)));
            encryptorNi.Encrypt(data, nonce, nonce, ciphertext, authenticationTag);
            var decryptorNi = new AesCbcHmacDecryptor(key.K.Slice(0, 24), EncryptionAlgorithm.Aes192CbcHmacSha384, new AesNiCbc192Decryptor(key.K.Slice(24)));
            var decryptor = new AesCbcHmacDecryptor(key.K.Slice(0, 24), EncryptionAlgorithm.Aes192CbcHmacSha384, new AesCbcDecryptor(key.K.Slice(24), EncryptionAlgorithm.Aes192CbcHmacSha384));
            bool decrypted = decryptor.TryDecrypt(ciphertext, nonce, nonce, authenticationTag, plaintext, out int bytesWritten);
            Assert.True(decrypted);
            Assert.Equal(data, plaintext.Slice(0, bytesWritten).ToArray());

            plaintext.Clear();
            decrypted = decryptorNi.TryDecrypt(ciphertext, nonce, nonce, authenticationTag, plaintext, out bytesWritten);
            Assert.True(decrypted);
            Assert.Equal(data, plaintext.Slice(0, bytesWritten).ToArray());
        }
#endif
    }

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
            var encryptor = new AesCbcHmacEncryptor(key, EncryptionAlgorithm.Aes256CbcHmacSha512);
            encryptor.Encrypt(data, nonce, nonce, ciphertext, authenticationTag);
            var decryptor = new AesCbcHmacDecryptor(key, EncryptionAlgorithm.Aes256CbcHmacSha512);
            bool decrypted = decryptor.TryDecrypt(ciphertext, nonce, nonce, authenticationTag, plaintext, out int bytesWritten);
            Assert.True(decrypted);
        }
#if NETCOREAPP3_0
        [Fact]
        public void EncryptFast_Decrypt()
        {
            var data = Encoding.UTF8.GetBytes("This is a test string for encryption.");
            var ciphertext = new Span<byte>(new byte[(data.Length + 16) & ~15]);
            var authenticationTag = new Span<byte>(new byte[64]);
            var plaintext = new Span<byte>(new byte[data.Length]);
            var key = SymmetricJwk.GenerateKey(512);
            var nonce = new byte[] { 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1 };
            var encryptor = new AesCbcHmacEncryptor(key, EncryptionAlgorithm.Aes256CbcHmacSha512);
            encryptor.Encrypt(data, nonce, nonce, ciphertext, authenticationTag);
            var decryptor = new AesCbcHmacDecryptor(key, EncryptionAlgorithm.Aes256CbcHmacSha512);
            bool decrypted = decryptor.TryDecrypt(ciphertext, nonce, nonce, authenticationTag, plaintext, out int bytesWritten);
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
        [InlineData("This is a test string for encryption.This is a test string for encryption.This is a test string for encryption.This is a test string for encryption.")]
        public void EncryptSimd_Decrypt(string value)
        {
            var data = Encoding.UTF8.GetBytes(value);
            var ciphertext = new Span<byte>(new byte[(data.Length + 16) & ~15]);
            var authenticationTag = new Span<byte>(new byte[64]);
            var plaintext = new Span<byte>(new byte[ciphertext.Length]);
            var key = new SymmetricJwk(Encoding.UTF8.GetBytes("ThisIsA128bitKey" + "ThisIsA128bitKey" + "ThisIsA128bitKey" + "ThisIsA128bitKey"));
            var nonce = Encoding.UTF8.GetBytes("ThisIsAnInitVect");
            var encryptorNi = new AesCbcHmacEncryptor(key.K.Slice(0, 32), EncryptionAlgorithm.Aes256CbcHmacSha512, new AesNiCbc128Encryptor(key.K.Slice(32)));
            encryptorNi.Encrypt(data, nonce, nonce, ciphertext, authenticationTag);
            var decryptorNi = new AesCbcHmacDecryptor(key.K.Slice(0, 32), EncryptionAlgorithm.Aes256CbcHmacSha512, new AesNiCbc128Decryptor(key.K.Slice(32)));
            bool decrypted = decryptorNi.TryDecrypt(ciphertext, nonce, nonce, authenticationTag, plaintext, out int bytesWritten);
            Assert.True(decrypted);
            Assert.Equal(data, plaintext.Slice(0, bytesWritten).ToArray());

            plaintext.Clear();
            decrypted = decryptorNi.TryDecrypt(ciphertext, nonce, nonce, authenticationTag, plaintext, out bytesWritten);
            Assert.True(decrypted);
            Assert.Equal(data, plaintext.Slice(0, bytesWritten).ToArray());
        }
#endif
    }
}