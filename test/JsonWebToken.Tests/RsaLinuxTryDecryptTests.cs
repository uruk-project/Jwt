using System;
using System.Security.Cryptography;
using Xunit;

namespace JsonWebToken.Tests
{
    public class RsaTryDecryptTests
    {
        [Fact]
        public void TryDecrypt()
        {
            var data = new byte[128];
            RandomNumberGenerator.Fill(data);

            var paddingMode = RSAEncryptionPadding.OaepSHA256;
            using (var rsa = RSA.Create())
            {
                rsa.KeySize = 2048;
                var encryptedData = rsa.Encrypt(data, paddingMode);

                var destination = new byte[256];
                var encrypted = rsa.TryEncrypt(data, destination, paddingMode, out int written);
                Assert.True(encrypted);

                var decryptedData = rsa.Decrypt(encryptedData, paddingMode);
                Assert.Equal(data, decryptedData);

                var decryptedDataLength = rsa.KeySize >> 3 > data.Length ? rsa.KeySize >> 3 : data.Length;
                var tryDecryptedData = new byte[decryptedDataLength];
                var decrypted = rsa.TryDecrypt(encryptedData, tryDecryptedData, paddingMode, out int bytesWritten);
                Assert.True(decrypted);
                Assert.Equal(data, tryDecryptedData.AsSpan(0, bytesWritten).ToArray());
                Assert.Equal(data.Length, bytesWritten);
            }
        }
    }
}
