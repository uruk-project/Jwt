using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.IO;
using System.Linq;
using System.Reflection;
using Xunit;

namespace JsonWebToken.Tests
{
    public class JsonWebTokenWriterTests
    {

        [Theory]
        [MemberData(nameof(GetDescriptors))]
        public void Write(JsonWebTokenDescriptor descriptor)
        {
            JsonWebTokenWriter writer = new JsonWebTokenWriter();
            var value = writer.WriteToken(descriptor);

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
                yield return new[] { jwt };
            }
        }
    }
}