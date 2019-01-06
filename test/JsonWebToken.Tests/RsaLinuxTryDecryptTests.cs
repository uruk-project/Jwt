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
            FillData(data);

            var paddingMode = RSAEncryptionPadding.OaepSHA256;
            using (var rsa = RSA.Create())
            {
                rsa.KeySize = 2048;
                var encryptedData = rsa.Encrypt(data, paddingMode);

                var destination = rsa.Encrypt(data, paddingMode);

                var decryptedData = rsa.Decrypt(encryptedData, paddingMode);
                Assert.Equal(data, decryptedData);

                var decryptedDataLength = rsa.KeySize >> 3 > data.Length ? rsa.KeySize >> 3 : data.Length;
                var tryDecryptedData = rsa.Decrypt(encryptedData, paddingMode);
                Assert.Equal(data, tryDecryptedData);
            }
        }

        private static void FillData(byte[] data)
        {
#if NETSTANDARD2_0 || NETCOREAPP2_0
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetNonZeroBytes(data);
            }
#else
            RandomNumberGenerator.Fill(data);
#endif
        }
    }
}
