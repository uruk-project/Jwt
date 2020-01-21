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
        protected static readonly TokenValidationParameters wilsonParametersWithoutSignature = new TokenValidationParameters()
        {
            ValidateAudience = true,
            ValidateIssuer = true,
            ValidateLifetime = true,
            ValidAudience = "636C69656E745F6964",
            ValidIssuer = "https://idp.example.com/",
            RequireSignedTokens = false,
            TokenDecryptionKey = JsonWebKey.Create(Tokens.EncryptionKey.ToString())
        };
        protected static readonly TokenValidationParameters wilsonParametersWithoutValidation = new TokenValidationParameters()
        {
            ValidateAudience = false,
            ValidateIssuer = false,
            ValidateLifetime = false,
            RequireSignedTokens = false,
            IssuerSigningKey = JsonWebKey.Create(Tokens.SigningKey.ToString()),
            TokenDecryptionKey = JsonWebKey.Create(Tokens.EncryptionKey.ToString())
        };

        static ValidateToken()
        {
            Microsoft.IdentityModel.Logging.IdentityModelEventSource.ShowPII = true;
        }

        public abstract TokenValidationResult Jwt(BenchmarkToken token);

        protected TokenValidationResult JwtCore(byte[] token, TokenValidationPolicy policy)
        {
            var result = Reader.TryReadToken(token, policy);
            if (!result.Succedeed)
            {
                ThrowException(result.Status.ToString());
            }

            return result;
        }

        public abstract ClaimsPrincipal Wilson(BenchmarkToken token);

        protected ClaimsPrincipal WilsonCore(string token, TokenValidationParameters parameters)
        {
            var result = Handler.ValidateToken(token, parameters, out var securityToken);
            if (result == null)
            {
                ThrowException($"{nameof(Handler.ValidateToken)} has returned 'null'.");
            }

            return result!;
        }

        public abstract Microsoft.IdentityModel.JsonWebTokens.TokenValidationResult WilsonJwt(BenchmarkToken token);

        protected Microsoft.IdentityModel.JsonWebTokens.TokenValidationResult WilsonJwtCore(string token, TokenValidationParameters parameters)
        {
            var result = Handler2.ValidateToken(token, parameters);
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

        public abstract void JoseDotNet(BenchmarkToken token);

        protected void JoseDotNetCore(string token, JweEncryption enc, JweAlgorithm alg, byte[] key)
        {
            var value = Jose.JWT.Decode<Dictionary<string, object>>(token, key: key, enc: enc/*JweEncryption.A128CBC_HS256*/, alg: alg/*JweAlgorithm.A128KW*/);
            if (value == null)
            {
                ThrowException($"{nameof(value)} is 'null'.");
            }
        }

        protected void JoseDotNetCore(string token, JwsAlgorithm alg, byte[] key)
        {
            var value = Jose.JWT.Decode<Dictionary<string, object>>(token, key: key, alg: alg /*JwsAlgorithm.HS256*/);
            if (value == null)
            {
                ThrowException($"{nameof(value)} is 'null'.");
            }
        }

        public abstract void JwtDotNet(BenchmarkToken token);

        protected void JwtDotNetCore(string token, byte[] key, bool verify)
        {
            var value = JwtDotNetDecoder.DecodeToObject(token, key, verify: verify);
            if (value == null)
            {
                ThrowException($"{nameof(value)} is 'null'.");
            }
        }

        [MethodImpl(MethodImplOptions.NoInlining)]
        protected static void ThrowException(string message)
        {
            throw new Exception(message);
        }

        public abstract IEnumerable<string> GetTokens();

        public IEnumerable<BenchmarkToken> GetTokenValues()
        {
            foreach (var item in GetTokens())
            {
                yield return new BenchmarkToken(item);
            }
        }

        public class BenchmarkToken
        {
            public BenchmarkToken(string name)
            {
                Name = name ?? throw new ArgumentNullException(nameof(name));
                TokenString = Tokens.ValidTokens[name];
                TokenBinary = Tokens.ValidBinaryTokens[name];
            }

            public string Name { get; }

            public string TokenString { get; }

            public byte[] TokenBinary { get; }

            public override string ToString()
            {
                return Name;
            }
        }
    }
}
