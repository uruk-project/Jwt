using System.Text;
using JsonWebToken.Cryptography;
using Xunit;

namespace JsonWebToken.Tests
{
    public class DirectKeyWrapTests
    {
        [Fact]
        public void Wrap()
        {
            var staticKey = new byte[] { 111, 27, 25, 52, 66, 29, 20, 78, 92, 176, 56, 240, 65, 208, 82, 112, 161, 131, 36, 55, 202, 236, 185, 172, 129, 23, 153, 194, 195, 48, 253, 182 };

            var kwp = new DirectKeyWrapper(SymmetricJwk.FromByteArray(staticKey), EncryptionAlgorithm.A128CbcHS256, KeyManagementAlgorithm.Dir);

            var header = new JwtHeader();
            var destination = new byte[kwp.GetKeyWrapSize()];
            var cek = kwp.WrapKey(null, header, destination);

            Assert.Equal(staticKey, cek.K.ToArray());
        }

        [Fact]
        public void Unwrap()
        {
            var staticKey = new byte[] { 111, 27, 25, 52, 66, 29, 20, 78, 92, 176, 56, 240, 65, 208, 82, 112, 161, 131, 36, 55, 202, 236, 185, 172, 129, 23, 153, 194, 195, 48, 253, 182 };

            var parsed = JwtHeaderDocument.TryParseHeader(Encoding.UTF8.GetBytes($"{{}}"), null, TokenValidationPolicy.NoValidation, out var jwtHeader, out var error);
            Assert.True(parsed);

            var kuwp = new DirectKeyUnwrapper(SymmetricJwk.FromByteArray(staticKey), EncryptionAlgorithm.A128CbcHS256, KeyManagementAlgorithm.Dir);

            byte[] unwrappedKey = new byte[kuwp.GetKeyUnwrapSize(staticKey.Length)];
            var unwrapped = kuwp.TryUnwrapKey(default, unwrappedKey, jwtHeader, out _);

            Assert.True(unwrapped);
            Assert.Equal(staticKey, unwrappedKey);
        }
    }
}
