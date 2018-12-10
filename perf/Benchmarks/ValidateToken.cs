using BenchmarkDotNet.Attributes;
using Jose;
using JWT;
using JWT.Algorithms;
using JWT.Serializers;
using Microsoft.IdentityModel.JsonWebTokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;

namespace JsonWebToken.Performance
{
    [Config(typeof(DefaultCoreConfig))]
    [BenchmarkCategory("CI-CD")]
    public class ValidateUnsignedToken : ValidateToken
    {
        [Benchmark(Baseline = true)]
        [ArgumentsSource(nameof(GetTokens))]
        public void Jwt(string token)
        {
            var result = Reader.TryReadToken(Tokens.ValidTokens[token].AsSpan(), TokenValidationPolicy.NoValidation);
            if (!result.Succedeed)
            {
                throw new Exception(result.Status.ToString());
            }
        }

        [Benchmark]
        [ArgumentsSource(nameof(GetTokens))]
        public void Wilson(string token)
        {
            var result = Handler.ValidateToken(Tokens.ValidTokens[token], wilsonParametersWithouSignature, out var securityToken);
            if (result == null)
            {
                throw new Exception();
            }
        }

        [Benchmark]
        [ArgumentsSource(nameof(GetTokens))]
        public void WilsonJwt(string token)
        {
            var result = Handler2.ValidateToken(Tokens.ValidTokens[token], wilsonParametersWithouSignature);
            if (result.SecurityToken == null)
            {
                throw new Exception();
            }
        }

        public IEnumerable<string> GetTokens()
        {
            yield return "JWT-empty";
            yield return "JWT-small";
            yield return "JWT-medium";
            yield return "JWT-big";
        }
    }

    [Config(typeof(DefaultCoreConfig))]
    [BenchmarkCategory("CI-CD")]
    public class ValidateSignedToken : ValidateToken
    {
        [Benchmark(Baseline = true)]
        [ArgumentsSource(nameof(GetTokens))]
        public void Jwt(string token)
        {
            var result = Reader.TryReadToken(Tokens.ValidTokens[token].AsSpan(), policyWithSignatureValidation);
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
        public void Wilson2(string token)
        {
            var result = Handler2.ValidateToken(Tokens.ValidTokens[token], wilsonParameters);
            if (result.SecurityToken == null)
            {
                throw new Exception();
            }
        }

        public IEnumerable<string> GetTokens()
        {
            yield return "JWS-empty";
            yield return "JWS-small";
            yield return "JWS-medium";
            yield return "JWS-big";
        }
    }

    [Config(typeof(DefaultCoreConfig))]
    [BenchmarkCategory("CI-CD")]
    public class ValidateEncryptedToken : ValidateToken
    {
        [Benchmark(Baseline = true)]
        [ArgumentsSource(nameof(GetTokens))]
        public void Jwt(string token)
        {
            var result = Reader.TryReadToken(Tokens.ValidTokens[token].AsSpan(), policyWithSignatureValidation);
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
        public void Wilson2(string token)
        {
            var result = Handler2.ValidateToken(Tokens.ValidTokens[token], wilsonParameters);
            if (result.SecurityToken == null)
            {
                throw new Exception();
            }
        }

        public IEnumerable<string> GetTokens()
        {
            yield return "JWE-empty";
            yield return "JWE-small";
            yield return "JWE-medium";
            yield return "JWE-big";
        }
    }

    public abstract class ValidateToken
    {
        private static readonly IJwtAlgorithm algorithm = new HMACSHA256Algorithm();
        private static readonly IJsonSerializer serializer = new JsonNetSerializer();
        private static readonly IBase64UrlEncoder urlEncoder = new JwtBase64UrlEncoder();
        private static readonly IDateTimeProvider dateTimeProvider = new UtcDateTimeProvider();
        public static readonly IJwtEncoder JwtDotNetEncoder = new JwtEncoder(algorithm, serializer, urlEncoder);
        public static readonly JwtDecoder JwtDotNetDecoder = new JwtDecoder(serializer, new JwtValidator(serializer, dateTimeProvider), urlEncoder);

        public static readonly JwtSecurityTokenHandler Handler = new JwtSecurityTokenHandler() { MaximumTokenSizeInBytes = 4 * 1024 * 1024 };
        public static readonly JsonWebTokenHandler Handler2 = new JsonWebTokenHandler();

        private static readonly SymmetricJwk SymmetricKey = Tokens.SigningKey;

        public static readonly JwtReader Reader = new JwtReader(Tokens.EncryptionKey);
        protected static readonly TokenValidationPolicy policyWithSignatureValidation = new TokenValidationPolicyBuilder().RequireSignature(SymmetricKey).Build();

        private static readonly Microsoft.IdentityModel.Tokens.JsonWebKey WilsonSharedKey = Microsoft.IdentityModel.Tokens.JsonWebKey.Create(SymmetricKey.ToString());

        protected static readonly Microsoft.IdentityModel.Tokens.TokenValidationParameters wilsonParameters = new Microsoft.IdentityModel.Tokens.TokenValidationParameters() { IssuerSigningKey = WilsonSharedKey, ValidateAudience = false, ValidateIssuer = false, ValidateLifetime = false, TokenDecryptionKey = Microsoft.IdentityModel.Tokens.JsonWebKey.Create(Tokens.EncryptionKey.ToString()) };
        protected static readonly Microsoft.IdentityModel.Tokens.TokenValidationParameters wilsonParametersWithouSignature = new Microsoft.IdentityModel.Tokens.TokenValidationParameters() {  ValidateAudience = false, ValidateIssuer = false, ValidateLifetime = false };

        //[Benchmark]
        //[ArgumentsSource(nameof(GetTokens))]
        public void JoseDotNet(string token)
        {
            if (token.StartsWith("JWE-"))
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

        //[Benchmark]
        [ArgumentsSource(nameof(GetNotEncryptedTokens))]
        public void JwtDotNet(string token)
        {
            var value = JwtDotNetDecoder.DecodeToObject(Tokens.ValidTokens[token], SymmetricKey.RawK, verify: true);
            if (value == null)
            {
                throw new Exception();
            }
        }
        
        public IEnumerable<string> GetNotEncryptedTokens()
        {
            yield return "JWS-empty";
            yield return "JWS-small";
            yield return "JWS-medium";
            yield return "JWS-big";
        }
    }
}
