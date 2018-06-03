using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;

namespace JsonWebTokens.Tests
{
    public static class Tokens
    {
        static Tokens()
        {
            var location = new Uri(typeof(Tokens).GetTypeInfo().Assembly.CodeBase).AbsolutePath;
            var dirPath = Path.GetDirectoryName(location);
            var jsonPath = Path.Combine(dirPath, "./resources/descriptors.json");
            var json = File.ReadAllText(jsonPath);
            Descriptors = JArray.Parse(json).Select(t => new JwtPayloadDescriptor(t));

            jsonPath = Path.Combine(dirPath, "./resources/jwts.json");
            json = File.ReadAllText(jsonPath);
            Jwts = JArray.Parse(json).Select(t => t.ToString());

            jsonPath = Path.Combine(dirPath, "./resources/invalid_jwts.json");
            json = File.ReadAllText(jsonPath);
            InvalidJwts = JArray.Parse(json).Select(t => new TokenState(t["jwt"].ToString(), (TokenValidationStatus)Enum.Parse(typeof(TokenValidationStatus), t["status"].ToString())));
        }

        private class JwtPayloadDescriptor : IJwtPayloadDescriptor
        {
            public JwtPayloadDescriptor(JToken token)
            {
                Audiences = new[] { token.Value<string>("aud") };
                var exp = token.Value<long?>("exp");
                ExpirationTime = exp.HasValue ? EpochTime.ToDateTime(exp.Value) : default(DateTime?);
                var iat = token.Value<long?>("iat");
                IssuedAt = iat.HasValue ? EpochTime.ToDateTime(iat.Value) : default(DateTime?);
                var nbf = token.Value<long?>("nbf");
                NotBefore = nbf.HasValue ? EpochTime.ToDateTime(nbf.Value) : default(DateTime?);
                Issuer = token.Value<string>("iss");
                JwtId = token.Value<string>("jti");
            }
            public string Subject { get; set; }
            public IReadOnlyList<string> Audiences { get; set; }
            public DateTime? ExpirationTime { get; set; }
            public DateTime? IssuedAt { get; set; }
            public string Issuer { get; set; }
            public string JwtId { get; set; }
            public DateTime? NotBefore { get; set; }
        }

        public static IEnumerable<IJwtPayloadDescriptor> Descriptors { get; }

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
}