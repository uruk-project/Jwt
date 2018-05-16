using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using Xunit;

namespace JsonWebToken.Tests
{
    public static class Keys
    {
        static Keys()
        {
            var location = new Uri(typeof(Keys).GetTypeInfo().Assembly.CodeBase).AbsolutePath;
            var dirPath = Path.GetDirectoryName(location);
            var keysPath = Path.Combine(dirPath, "./resources/jwks.json"); ;
            var jwks = File.ReadAllText(keysPath);
            Jwks = new JsonWebKeySet(jwks);
        }

        public static JsonWebKeySet Jwks { get; }
    }

    public static class Tokens
    {
        static Tokens()
        {
            var location = new Uri(typeof(Tokens).GetTypeInfo().Assembly.CodeBase).AbsolutePath;
            var dirPath = Path.GetDirectoryName(location);
            var jsonPath = Path.Combine(dirPath, "./resources/descriptors.json");
            var json = File.ReadAllText(jsonPath);
            Descriptors = JArray.Parse(json).Select(t => new JsonWebTokenDescriptor(t.ToString()));

            jsonPath = Path.Combine(dirPath, "./resources/jwts.json");
            json = File.ReadAllText(jsonPath);
            Jwts = JArray.Parse(json).Select(t => t.ToString());

            jsonPath = Path.Combine(dirPath, "./resources/invalid_jwts.json");
            json = File.ReadAllText(jsonPath);
            InvalidJwts = JArray.Parse(json).Select(t => new TokenState(t["jwt"].ToString(), (TokenValidationStatus)Enum.Parse(typeof(TokenValidationStatus), t["status"].ToString())));
        }

        public static IEnumerable<JsonWebTokenDescriptor> Descriptors { get; }

        public static IEnumerable<string> Jwts { get; }

        public static IEnumerable<TokenState> InvalidJwts { get; }

        public class TokenState
        {
            public TokenState(string jwt, TokenValidationStatus status)
            {
                Jwt = jwt;
                Status = status;
            }

            public string Jwt { get; }
            public TokenValidationStatus Status { get; }
        }
    }

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
            var validationParameters = new TokenValidationParameters
            {
                ValidAudience = "636C69656E745F6964",
                ValidIssuer = "https://idp.example.com/"
            };

            var result = reader.TryReadToken(jwt, validationParameters);
            Assert.Equal(TokenValidationStatus.Success, result.Status);
        }

        [Theory]
        [MemberData(nameof(GetInvalidTokens))]
        public void ReadJwt_Invalid(string jwt, TokenValidationStatus expectedStatus)
        {
            var reader = new JsonWebTokenReader(Keys.Jwks);
            var validationParameters = new TokenValidationParameters
            {
                ValidAudience = "636C69656E745F6964",
                ValidIssuer = "https://idp.example.com/"
            };

            var result = reader.TryReadToken(jwt, validationParameters);
            Assert.Equal(expectedStatus, result.Status);
        }

        [Theory]
        [MemberData(nameof(GetInvalidValidationParameters))]
        public void InvalidValidationParameters_ThrowsException(TokenValidationParameters parameters, Type exceptionType)
        {
            var reader = new JsonWebTokenReader(Keys.Jwks);

            Assert.Throws(exceptionType, () => reader.TryReadToken(Tokens.Jwts.First(), parameters));
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

        public static IEnumerable<object[]> GetInvalidValidationParameters()
        {
            yield return new object[] {
                new TokenValidationParameters
                {
                    ValidateIssuer = false,
                    ValidateAudience = true,
                    ValidAudience = null
                },
                typeof(ArgumentException)
            };
            yield return new object[] {
                new TokenValidationParameters
                {
                    ValidateIssuer = false,
                    ValidateAudience = true,
                    ValidAudience = string.Empty
                },
                typeof(ArgumentException)
            };
            yield return new object[] {
                new TokenValidationParameters
                {
                    ValidateAudience = false,
                    ValidateIssuer = true,
                    ValidIssuer = null
                },
                typeof(ArgumentException)
            };
            yield return new object[] {
                new TokenValidationParameters
                {
                    ValidateAudience = false,
                    ValidateIssuer = true,
                    ValidIssuer = string.Empty
                },
                typeof(ArgumentException)
            };
        }

    }
}