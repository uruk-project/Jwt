using System.Collections.Generic;
using Xunit;

namespace JsonWebToken.Tests
{
    public class JsonWebTokenReaderTests
    {
        public static IEnumerable<object[]> GetJwts()
        {
            foreach (var jwt in Tokens.Descriptors)
            {
                yield return new[] { jwt };
            }
        }

        [Theory]
        [MemberData(nameof(GetValidTokens))]
        public void ReadJwt_Valid(string jwt)
        {
            var reader = new JsonWebTokenReader(Keys.Jwks);
            var validationParameters = new TokenValidationBuilder()
                    .RequireSignature(Keys.Jwks)
                    .AddLifetimeValidation()
                    .RequireAudience("636C69656E745F6964")
                    .RequireIssuer("https://idp.example.com/")
                    .Build();

            var result = reader.TryReadToken(jwt, validationParameters);
            Assert.Equal(TokenValidationStatus.Success, result.Status);
        }

        [Theory]
        [MemberData(nameof(GetInvalidTokens))]
        public void ReadJwt_Invalid(string jwt, TokenValidationStatus expectedStatus)
        {
            var reader = new JsonWebTokenReader(Keys.Jwks);
            var validationParameters = new TokenValidationBuilder()
                    .RequireSignature(Keys.Jwks)
                    .AddLifetimeValidation()
                    .RequireAudience("636C69656E745F6964")
                    .RequireIssuer("https://idp.example.com/")
                    .Build();

            var result = reader.TryReadToken(jwt, validationParameters);
            Assert.Equal(expectedStatus, result.Status);
        }

        public static IEnumerable<object[]> GetValidTokens()
        {
            foreach (var item in Tokens.Jwts)
            {
                yield return new object[] { item };
            }
        }

        public static IEnumerable<object[]> GetInvalidTokens()
        {
            foreach (var item in Tokens.InvalidJwts)
            {
                yield return new object[] { item.Jwt, item.Status };
            }
        }
    }
}