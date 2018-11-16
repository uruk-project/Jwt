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

                var decryptedData = rsa.Decrypt(encryptedData, paddingMode);
                Assert.Equal(data, decryptedData);

                var tryDecryptedData = new byte[140];
                var decrypted = rsa.TryDecrypt(encryptedData, tryDecryptedData, paddingMode, out int bytesWritten);
                Assert.True(decrypted);
                Assert.Equal(data, tryDecryptedData);
                Assert.Equal(data.Length, bytesWritten);
            }
        }
    }
}
