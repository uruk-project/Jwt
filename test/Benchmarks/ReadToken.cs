using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Running;
using Jose;
using JWT;
using JWT.Serializers;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;

namespace JsonWebToken.Performance
{
    [Config(typeof(DefaultCoreConfig))]
    public class ReadToken
    {
        private static readonly IJsonSerializer serializer = new JsonNetSerializer();
        private static readonly IBase64UrlEncoder urlEncoder = new JwtBase64UrlEncoder();
        private static readonly IDateTimeProvider dateTimeProvider = new UtcDateTimeProvider();
        public static readonly JwtDecoder JwtDotNetDecoder = new JwtDecoder(serializer, new JwtValidator(serializer, dateTimeProvider), urlEncoder);

        private static readonly SymmetricJwk SymmetricKey = Tokens.SigningKey;
        public static readonly JsonWebTokenReader Reader = new JsonWebTokenReader(Tokens.EncryptionKey);
        private static readonly TokenValidationParameters validationParameters = TokenValidationParameters.NoValidation;
        public static readonly JwtSecurityTokenHandler Handler = new JwtSecurityTokenHandler() { MaximumTokenSizeInBytes = 4 * 1024 * 1024 };

        [Benchmark(Baseline = true)]
        [ArgumentsSource(nameof(GetTokens))]
        public void Jwt(string token)
        {
            var result = Reader.TryReadToken(Tokens.ValidTokens[token].AsSpan(), validationParameters);
            if (!result.Succedeed)
            {
                throw new Exception(result.Status.ToString());
            }
        }

        [Benchmark]
        [ArgumentsSource(nameof(GetTokens))]
        public void Wilson(string token)
        {
            if (token.StartsWith("JWE-"))
            {
                // ReadJwtToken does not read the encrpted token
                var parameters = new Microsoft.IdentityModel.Tokens.TokenValidationParameters
                {
                    ValidateActor = false,
                    ValidateIssuer = false,
                    ValidateIssuerSigningKey = false,
                    ValidateLifetime=false,
                    ValidateTokenReplay=false,
                    ValidateAudience = false,
                    IssuerSigningKey = new Microsoft.IdentityModel.Tokens.JsonWebKey(Tokens.SigningKey.ToString()),
                    TokenDecryptionKey = new Microsoft.IdentityModel.Tokens.JsonWebKey(Tokens.EncryptionKey.ToString())
                };

                var result = Handler.ValidateToken(Tokens.ValidTokens[token], parameters, out var securityToken);
                if (result == null)
                {
                    throw new Exception();
                }
            }
            else
            {
                var result = Handler.ReadJwtToken(Tokens.ValidTokens[token]);
                if (result == null)
                {
                    throw new Exception();
                }
            }
        }

        [Benchmark]
        [ArgumentsSource(nameof(GetTokens))]
        public void JoseDotNet(string token)
        {
            if (token.StartsWith("JWE-"))
            {
                var jwt = Jose.JWT.Decode(Tokens.ValidTokens[token], key: Tokens.EncryptionKey.RawK, enc: JweEncryption.A128CBC_HS256, alg: JweAlgorithm.A128KW);
                var value = Jose.JWT.Decode<Dictionary<string, object>>(jwt, key: Tokens.SigningKey.RawK, alg: JwsAlgorithm.HS256);
                if (value == null)
                {
                    throw new Exception();
                }
            }
            else
            {
                var value = Jose.JWT.Decode<Dictionary<string, object>>(Tokens.ValidTokens[token], key: Tokens.SigningKey.RawK, alg: JwsAlgorithm.HS256);
                if (value == null)
                {
                    throw new Exception();
                }
            }
        }

        [Benchmark]
        [ArgumentsSource(nameof(GetNotEncryptedTokens))]
        public void JwtDotNet(string token)
        {
            var value = JwtDotNetDecoder.DecodeToObject(Tokens.ValidTokens[token]);
            if (value == null)
            {
                throw new Exception();
            }
        }
        public IEnumerable<object[]> GetTokens()
        {
            yield return new[] { "JWS-empty" };
            yield return new[] { "JWS-small" };
            yield return new[] { "JWS-medium" };
            yield return new[] { "JWS-big" };
            yield return new[] { "JWE-empty" };
            yield return new[] { "JWE-small" };
            yield return new[] { "JWE-medium" };
            yield return new[] { "JWE-big" };
        }

        public IEnumerable<object[]> GetNotEncryptedTokens()
        {
            yield return new[] { "JWS-empty" };
            yield return new[] { "JWS-small" };
            yield return new[] { "JWS-medium" };
            yield return new[] { "JWS-big" };
        }
    }
}
