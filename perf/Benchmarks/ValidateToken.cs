using Jose;
using JWT;
using JWT.Algorithms;
using JWT.Serializers;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Runtime.CompilerServices;
using System.Security.Claims;

namespace JsonWebToken.Performance
{
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
        protected static readonly TokenValidationPolicy tokenValidationPolicy
            = new TokenValidationPolicyBuilder()
                .RequireSignature(SymmetricKey)
                .RequireAudience("636C69656E745F6964")
                .RequireIssuer("https://idp.example.com/")
                .EnableLifetimeValidation()
                .Build();

        protected static readonly TokenValidationPolicy tokenValidationPolicyWithoutSignature
            = new TokenValidationPolicyBuilder()
                .IgnoreSignature()
                .AcceptUnsecureToken()
                .RequireAudience("636C69656E745F6964")
                .RequireIssuer("https://idp.example.com/")
                .EnableLifetimeValidation()
                .Build();

        private static readonly JsonWebKey WilsonSharedKey = JsonWebKey.Create(SymmetricKey.ToString());

        protected static readonly TokenValidationParameters wilsonParameters = new TokenValidationParameters()
        {
            IssuerSigningKey = WilsonSharedKey,
            ValidateAudience = true,
            ValidateIssuer = true,
            ValidateLifetime = true,
            ValidAudience = "636C69656E745F6964",
            ValidIssuer = "https://idp.example.com/",
            TokenDecryptionKey = JsonWebKey.Create(Tokens.EncryptionKey.ToString())
        };
        protected static readonly TokenValidationParameters wilsonParametersWithouSignature = new TokenValidationParameters()
        {
            ValidateAudience = true,
            ValidateIssuer = true,
            ValidateLifetime = true,
            ValidAudience = "636C69656E745F6964",
            ValidIssuer = "https://idp.example.com/",
            RequireSignedTokens = false
        };  
        protected static readonly TokenValidationParameters wilsonParametersWithoutValidation = new TokenValidationParameters()
        {
            ValidateAudience = false,
            ValidateIssuer = false,
            ValidateLifetime = false,
            RequireSignedTokens = false
        };

        public abstract TokenValidationResult Jwt(string token);

        protected TokenValidationResult JwtCore(string token, TokenValidationPolicy policy)
        {
            var result = Reader.TryReadToken(Tokens.ValidBinaryTokens[token], policy);
            if (!result.Succedeed)
            {
                ThrowException(result.Status.ToString());
            }

            return result;
        }

        public abstract ClaimsPrincipal Wilson(string token);

        protected ClaimsPrincipal WilsonCore(string token, TokenValidationParameters parameters)
        {
            var result = Handler.ValidateToken(Tokens.ValidTokens[token], parameters, out var securityToken);
            if (result == null)
            {
                ThrowException($"{nameof(Handler.ValidateToken)} has returned 'null'.");
            }

            return result!;
        }

        public abstract Microsoft.IdentityModel.JsonWebTokens.TokenValidationResult WilsonJwt(string token);

        protected Microsoft.IdentityModel.JsonWebTokens.TokenValidationResult WilsonJwtCore(string token, TokenValidationParameters parameters)
        {
            var result = Handler2.ValidateToken(Tokens.ValidTokens[token], parameters);
            if (result == null)
            {
                ThrowException($"{nameof(Handler2.ValidateToken)} has returned 'null'.");
            }

            if (result!.SecurityToken == null)
            {
                ThrowException($"{nameof(result.SecurityToken)} is 'null'.");
            }

            return result;
        }

        //[Benchmark]
        //[ArgumentsSource(nameof(GetTokens))]
        public void JoseDotNet(string token)
        {
            if (token.StartsWith("JWE-"))
            {
                var value = Jose.JWT.Decode<Dictionary<string, object>>(Tokens.ValidTokens[token], key: Tokens.EncryptionKey.K.ToArray(), enc: JweEncryption.A128CBC_HS256, alg: JweAlgorithm.A128KW);
                if (value == null)
                {
                    throw new Exception();
                }
            }
            else
            {
                var value = Jose.JWT.Decode<Dictionary<string, object>>(Tokens.ValidTokens[token], key: Tokens.SigningKey.K.ToArray(), alg: JwsAlgorithm.HS256);
                if (value == null)
                {
                    throw new Exception();
                }
            }
        }

        //[Benchmark]
        //[ArgumentsSource(nameof(GetNotEncryptedTokens))]
        public void JwtDotNet(string token)
        {
            var value = JwtDotNetDecoder.DecodeToObject(Tokens.ValidTokens[token], SymmetricKey.K.ToArray(), verify: true);
            if (value == null)
            {
                throw new Exception();
            }
        }

        [MethodImpl(MethodImplOptions.NoInlining)]
        protected static void ThrowException(string message)
        {
            throw new Exception(message);
        }
    }
}
