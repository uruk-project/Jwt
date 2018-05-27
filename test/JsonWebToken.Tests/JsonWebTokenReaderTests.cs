using System.Collections.Generic;
using System.Net;
using System.Net.Http;
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

        [Fact(Skip = "Proxy")]
        public void ReadJwt_HttpKeyProvider_Valid()
        {
            var proxy = new WebProxy("http://localhost:8888")
            {
                Credentials = CredentialCache.DefaultNetworkCredentials
            };
            var reader = new JsonWebTokenReader(Keys.Jwks);
            var validationParameters = new TokenValidationBuilder()
                    .RequireSignature("https://demo.identityserver.io/.well-known/openid-configuration/jwks", new HttpClientHandler() { Proxy = proxy })
                    .Build();

            var jwt = "eyJhbGciOiJSUzI1NiIsImtpZCI6IjQ5OGJmN2Y5MjU2MjJiYjUwZGM0NzNkNWMzYmI3NmI0IiwidHlwIjoiSldUIn0.eyJuYmYiOjE1MjcxOTE0NDQsImV4cCI6MTUyNzE5NTA0NCwiaXNzIjoiaHR0cHM6Ly9kZW1vLmlkZW50aXR5c2VydmVyLmlvIiwiYXVkIjpbImh0dHBzOi8vZGVtby5pZGVudGl0eXNlcnZlci5pby9yZXNvdXJjZXMiLCJhcGkiXSwiY2xpZW50X2lkIjoiY2xpZW50Iiwic2NvcGUiOlsiYXBpIl19.kYYiVoSMj81P0qzgMerfwcxGOSEZde5hjCiRL6flXdrZ3iFoiQ-z98nC5hAyaYwL2PJ9aLJ5B4Q2jW9PU6NS7hHHPbgU-WbbHqgAvLL7zGywUnnpkk39_OqUk9Y7cgT-ObNCbIvmRF0xvFWrEu7Wllfia0RRPoqbr1BQW3LV8LKS0ocz-BtwLbIdAddgR5ZQ28nBHgycWd7t8rmiZQVGw1hRtJAc1Mgs9qXU1bqDuP5__B4zJSpfpS711wmkkHOIYOfgpdih28gzE3Ot1Im2zuyOZ6Q9wM2zWttKxpNC2lBulP6kRr9lT6PTQ-RnLVaWgoBa4XmaoMJ0se9SqE1Stw";
            var result = reader.TryReadToken(jwt, validationParameters);
            Assert.Equal(TokenValidationStatus.Success, result.Status);
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