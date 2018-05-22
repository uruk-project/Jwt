using System.Collections.Generic;
using System.Linq;
using Xunit;

namespace JsonWebToken.Tests
{
    public class JsonWebTokenWriterTests
    {
        public JsonWebTokenWriterTests()
        {
            Microsoft.IdentityModel.Logging.IdentityModelEventSource.ShowPII = true;
        }

        [Theory]
        [MemberData(nameof(GetDescriptors))]
        public void Write(JsonWebTokenDescriptor descriptor)
        {
            JsonWebTokenWriter writer = new JsonWebTokenWriter();
            var value = writer.WriteToken(descriptor);

            var reader = new JsonWebTokenReader(Keys.Jwks);
            var result = reader.TryReadToken(value, TokenValidationParameters.NoValidation);
            var jwt = result.Token;

            Assert.Equal(descriptor.IssuedAt, jwt.Payload.Iat);
            Assert.Equal(descriptor.Expires, jwt.Expires);
            Assert.Equal(descriptor.Issuer, jwt.Issuer);
            Assert.Equal(descriptor.Audience, jwt.Audiences.First());
            Assert.Equal(descriptor.Id, jwt.Id);
        }

        public static IEnumerable<object[]> GetDescriptors()
        {
            foreach (var key in Keys.Jwks.Keys.Where(k => k.Use == JsonWebKeyUseNames.Sig))
            {
                foreach (var jwt in Tokens.Descriptors)
                {
                    jwt.SigningKey = key;
                    //yield return new object[] { jwt };
                }
            }

            var encryptionAlgorithms = new[] { SecurityAlgorithms.Aes128CbcHmacSha256, SecurityAlgorithms.Aes192CbcHmacSha384, SecurityAlgorithms.Aes256CbcHmacSha512 };
            foreach (var encKey in Keys.Jwks.Keys.Where(k => k.Use == JsonWebKeyUseNames.Enc && k.Kty == JsonWebAlgorithmsKeyTypes.Octet))
            {
                foreach (var enc in encryptionAlgorithms)
                {
                    if (!encKey.IsSupportedAlgorithm(enc))
                    {
                        continue;
                    }

                    var sigKey = Keys.Jwks.Keys.First(k => k.Use == JsonWebKeyUseNames.Sig);
                    foreach (var jwt in Tokens.Descriptors)
                    {
                        jwt.SigningKey = sigKey;
                        jwt.EncryptingKey = encKey;
                        jwt.EncryptionAlgorithm = enc;
                        yield return new object[] { jwt };
                    }
                }
            }
        }
    }
}