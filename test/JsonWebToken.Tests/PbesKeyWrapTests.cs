using System.Text;
using Xunit;
using JsonWebToken.Cryptography;
using System;
using System.Security.Cryptography;

namespace JsonWebToken.Tests
{
    public class PbesKeyWrapTests
    {
        private readonly string _password = "Thus from my lips, by yours, my sin is purged.";

        [Fact]
        public void Wrap_Rfc7518_Appendix_C()
        {
            var salt = new byte[16] { 217, 96, 147, 112, 150, 117, 70, 247, 127, 8, 155, 137, 174, 42, 80, 215 };
            var staticKey = new byte[] { 111, 27, 25, 52, 66, 29, 20, 78, 92, 176, 56, 240, 65, 208, 82, 112, 161, 131, 36, 55, 202, 236, 185, 172, 129, 23, 153, 194, 195, 48, 253, 182 };

            var expectedEncryptedKey = new byte[] { 78, 186, 151, 59, 11, 141, 81, 240, 213, 245, 83, 211, 53, 188, 134, 188, 66, 125, 36, 200, 222, 124, 5, 103, 249, 52, 117, 184, 140, 81, 246, 158, 161, 177, 20, 33, 245, 57, 59, 4 };
            var kwp = new Pbes2KeyWrapper(
                PasswordBasedJwk.FromPassphrase(_password), 
                EncryptionAlgorithm.A128CbcHS256, 
                KeyManagementAlgorithm.Pbes2HS256A128KW, 
                4096,
                (uint)salt.Length, 
                new StubSaltGenerator(salt));

            var header = new JwtHeader
            {
                { JwtHeaderParameterNames.Alg, KeyManagementAlgorithm.Pbes2HS256A128KW.Name },
                { JwtHeaderParameterNames.Enc, EncryptionAlgorithm.A128CbcHS256.Name }
            };
            var destination = new byte[kwp.GetKeyWrapSize()];
            var cek = kwp.WrapKey(SymmetricJwk.FromByteArray(staticKey), header, destination);

            Assert.Equal(expectedEncryptedKey, destination);
            Assert.True(header.TryGetValue("p2s", out var jwtMember));
            Assert.Equal("2WCTcJZ1Rvd_CJuJripQ1w", (string)jwtMember.Value);
            Assert.True(header.TryGetValue("p2c", out jwtMember));
            Assert.Equal(4096u, (uint)jwtMember.Value);
        }

        [Fact]
        public void Unwrap()
        {
            var expectedStaticKey = new byte[] { 111, 27, 25, 52, 66, 29, 20, 78, 92, 176, 56, 240, 65, 208, 82, 112, 161, 131, 36, 55, 202, 236, 185, 172, 129, 23, 153, 194, 195, 48, 253, 182 };
            var wrappedKey = new byte[] { 78, 186, 151, 59, 11, 141, 81, 240, 213, 245, 83, 211, 53, 188, 134, 188, 66, 125, 36, 200, 222, 124, 5, 103, 249, 52, 117, 184, 140, 81, 246, 158, 161, 177, 20, 33, 245, 57, 59, 4 };
            var parsed = JwtHeaderDocument.TryParseHeader(Encoding.UTF8.GetBytes($"{{\"p2s\":\"2WCTcJZ1Rvd_CJuJripQ1w\",\"p2c\":4096}}"), null, TokenValidationPolicy.NoValidation, out var jwtHeader, out var error);
            Assert.True(parsed);

            var kuwp = new Pbes2KeyUnwrapper(PasswordBasedJwk.FromPassphrase(_password), EncryptionAlgorithm.A128CbcHS256, KeyManagementAlgorithm.Pbes2HS256A128KW);

            byte[] unwrappedKey = new byte[kuwp.GetKeyUnwrapSize(wrappedKey.Length)];
            var unwrapped = kuwp.TryUnwrapKey(wrappedKey, unwrappedKey, jwtHeader, out _);

            Assert.True(unwrapped);
            Assert.Equal(expectedStaticKey, unwrappedKey);
        }

#if SUPPORT_CRYPTO_SPAN
        [Fact]
        public void Pbkdf2_DeriveKey()
        {
            var salt = new byte[16] { 217, 96, 147, 112, 150, 117, 70, 247, 127, 8, 155, 137, 174, 42, 80, 215 };
            var password = Utf8.GetBytes(_password);
            using var pbkdf2_managed = new Rfc2898DeriveBytes(password, salt, 4096, HashAlgorithmName.SHA256);
            var result1 = pbkdf2_managed.GetBytes(16);


            Span<byte> result2 = stackalloc byte[16];
            Pbkdf2.DeriveKey(password, salt, Sha256.Shared, 4096, result2);

            Assert.Equal(result1, result2.ToArray());
        }
#endif

        internal class StubSaltGenerator : ISaltGenerator
        {
            private readonly byte[] _value;

            public StubSaltGenerator(byte[] value)
            {
                _value = value;
            }

            public void Generate(Span<byte> salt)
            {
                _value.CopyTo(salt);
            }
        }
    }
}
