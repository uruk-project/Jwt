using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Running;
using Jose;
using JWT;
using JWT.Algorithms;
using JWT.Serializers;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;

namespace JsonWebToken.Performance
{
    [Config(typeof(DefaultCoreConfig))]
    public class ValidateToken
    {
        private static readonly IJwtAlgorithm algorithm = new HMACSHA256Algorithm();
        private static readonly IJsonSerializer serializer = new JsonNetSerializer();
        private static readonly IBase64UrlEncoder urlEncoder = new JwtBase64UrlEncoder();
        private static readonly IDateTimeProvider dateTimeProvider = new UtcDateTimeProvider();
        public static readonly IJwtEncoder JwtDotNetEncoder = new JwtEncoder(algorithm, serializer, urlEncoder);
        public static readonly JwtDecoder JwtDotNetDecoder = new JwtDecoder(serializer, new JwtValidator(serializer, dateTimeProvider), urlEncoder);

        public static readonly JwtSecurityTokenHandler Handler = new JwtSecurityTokenHandler() { MaximumTokenSizeInBytes = 4 * 1024 * 1024 };

        private static readonly SymmetricJwk SymmetricKey = Tokens.SigningKey;

        public static readonly JsonWebTokenReader Reader = new JsonWebTokenReader(Tokens.EncryptionKey);
        private static readonly TokenValidationParameters validationParameters = new TokenValidationBuilder().RequireSignature(SymmetricKey).Build();

        private static readonly Microsoft.IdentityModel.Tokens.JsonWebKey WilsonSharedKey = Microsoft.IdentityModel.Tokens.JsonWebKey.Create(SymmetricKey.ToString());

        private static readonly Microsoft.IdentityModel.Tokens.TokenValidationParameters wilsonParameters = new Microsoft.IdentityModel.Tokens.TokenValidationParameters() { IssuerSigningKey = WilsonSharedKey, ValidateAudience = false, ValidateIssuer = false, ValidateLifetime = false, TokenDecryptionKey = Microsoft.IdentityModel.Tokens.JsonWebKey.Create(Tokens.EncryptionKey.ToString()) };

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
            var result = Handler.ValidateToken(Tokens.ValidTokens[token], wilsonParameters, out var securityToken);
            if (result == null)
            {
                throw new Exception();
            }
        }

        [Benchmark]
        [ArgumentsSource(nameof(GetTokens))]
        public void JoseDotNet(string token)
        {
            if (token.StartsWith("enc-"))
            {
                var value = Jose.JWT.Decode<Dictionary<string, object>>(Tokens.ValidTokens[token], key: Tokens.EncryptionKey.RawK, enc: JweEncryption.A128CBC_HS256, alg: JweAlgorithm.A128KW);
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
            var value = JwtDotNetDecoder.DecodeToObject(Tokens.ValidTokens[token], SymmetricKey.RawK, verify: true);
            if (value == null)
            {
                throw new Exception();
            }
        }

        public IEnumerable<object[]> GetTokens()
        {
            yield return new[] { "empty" };
            yield return new[] { "small" };
            yield return new[] { "medium" };
            yield return new[] { "big" };
            yield return new[] { "enc-empty" };
            yield return new[] { "enc-small" };
            yield return new[] { "enc-medium" };
            yield return new[] { "enc-big" };
        }

        public IEnumerable<object[]> GetNotEncryptedTokens()
        {
            yield return new[] { "empty" };
            yield return new[] { "small" };
            yield return new[] { "medium" };
            yield return new[] { "big" };
        }
    }
}
