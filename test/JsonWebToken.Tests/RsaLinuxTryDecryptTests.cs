using System.Security.Cryptography;
using Xunit;

namespace JsonWebToken.Tests
{
    public class RsaLinuxTryDecryptTests
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
                decryptedData = new byte[128];

                var decrypted = rsa.TryDecrypt(encryptedData, decryptedData, paddingMode, out int bytesWritten);
                Assert.True(decrypted);
                Assert.Equal(data, decryptedData);
            }
        }
    }
}
