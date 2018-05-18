using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
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
        public void Write(JsonWebTokenDescriptor descriptor, JsonWebKey key)
        {
            JsonWebTokenWriter writer = new JsonWebTokenWriter();
            descriptor.SigningKey = key;
            var value = writer.WriteToken(descriptor, useSpan: true);

            var handler = new JwtSecurityTokenHandler();
            var jwt = handler.ReadJwtToken(value);

            Assert.Equal(EpochTime.GetIntDate(descriptor.IssuedAt), jwt.Payload.Iat.Value);
            Assert.Equal(descriptor.Expires, jwt.ValidTo);
            Assert.Equal(descriptor.Issuer, jwt.Issuer);
            Assert.Equal(descriptor.Audience, jwt.Audiences.First());
            Assert.Equal(descriptor.Id, jwt.Id);
        }

        public static IEnumerable<object[]> GetDescriptors()
        {
            foreach (var jwt in Tokens.Descriptors)
            {
                foreach (var key in Keys.Jwks.Keys)
                {
                    yield return new object[] { jwt, key };
                }
            }
        }
    }
}