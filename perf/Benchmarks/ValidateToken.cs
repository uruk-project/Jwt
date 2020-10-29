using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using Jose;
using JWT;
using JWT.Algorithms;
using JWT.Serializers;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace JsonWebToken.Performance
{
    public abstract class ValidateToken
    {
        private static readonly IJwtAlgorithm algorithm = new HMACSHA256Algorithm();
        private static readonly IJsonSerializer serializer = new JsonNetSerializer();
        private static readonly IBase64UrlEncoder urlEncoder = new JwtBase64UrlEncoder();
        private static readonly IDateTimeProvider dateTimeProvider = new UtcDateTimeProvider();
        public static readonly IJwtEncoder JwtDotNetEncoder = new JwtEncoder(algorithm, serializer, urlEncoder);
        public static readonly JwtDecoder JwtDotNetDecoder = new JwtDecoder(serializer, new JwtValidator(serializer, dateTimeProvider), urlEncoder, algorithm);

        public static readonly JwtSecurityTokenHandler Handler = new JwtSecurityTokenHandler() { MaximumTokenSizeInBytes = 4 * 1024 * 1024 };
        public static readonly JsonWebTokenHandler Handler2 = new JsonWebTokenHandler();

        private static readonly SymmetricJwk SymmetricKey = Tokens.SigningKey;

        public static readonly JwtReader Reader = new JwtReader();
        protected static readonly TokenValidationPolicy tokenValidationPolicy
            = new TokenValidationPolicyBuilder()
                .RequireSignature(SymmetricKey)
                .RequireAudience("636C69656E745F6964")
                .RequireIssuer("https://idp.example.com/")
                .EnableLifetimeValidation()
                .WithDecryptionKey(Tokens.EncryptionKey)
                .Build();

        protected static readonly TokenValidationPolicy tokenValidationPolicyWithoutSignature
            = new TokenValidationPolicyBuilder()
                .IgnoreSignature()
                .AcceptUnsecureToken()
                .RequireAudience("636C69656E745F6964")
                .RequireIssuer("https://idp.example.com/")
                .EnableLifetimeValidation()
                .WithDecryptionKey(Tokens.EncryptionKey)
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

        public abstract Jwt JsonWebToken(BenchmarkToken token);

        protected bool JwtCore(byte[] token, TokenValidationPolicy policy, out Jwt jwt)
        {
            return Jwt.TryParse(token, policy, out jwt);
        }

        public abstract ClaimsPrincipal Wilson(BenchmarkToken token);

        protected ClaimsPrincipal WilsonCore(string token, TokenValidationParameters parameters)
        {
            return Handler.ValidateToken(token, parameters, out var securityToken);
        }

        public abstract Microsoft.IdentityModel.Tokens.TokenValidationResult WilsonJwt(BenchmarkToken token);

        protected Microsoft.IdentityModel.Tokens.TokenValidationResult WilsonJwtCore(string token, TokenValidationParameters parameters)
        {
            return Handler2.ValidateToken(token, parameters);
        }

        public abstract Dictionary<string, object> jose_jwt(BenchmarkToken token);

        protected Dictionary<string, object> JoseDotNetCore(string token, JweEncryption enc, JweAlgorithm alg, byte[] key)
        {
            return Jose.JWT.Decode<Dictionary<string, object>>(token, key: key, enc: enc/*JweEncryption.A128CBC_HS256*/, alg: alg/*JweAlgorithm.A128KW*/);
        }

        protected Dictionary<string, object> JoseDotNetCore(string token, JwsAlgorithm alg, byte[]? key)
        {
            return Jose.JWT.Decode<Dictionary<string, object>>(token, key: key, alg: alg /*JwsAlgorithm.HS256*/);
        }

        public abstract IDictionary<string, object> Jwt_Net(BenchmarkToken token);

        protected IDictionary<string, object> JwtDotNetCore(string token, byte[] key, bool verify)
        {
            return JwtDotNetDecoder.DecodeToObject(token, key, verify: verify);
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
                TokenBinary = Encoding.UTF8.GetBytes(TokenString);
                var parts = TokenString.Split('.');
                parts[2] = new string(parts[2].Reverse().ToArray());
                InvalidTokenString = parts[0] + "." + parts[1] + "." + parts[2];
                InvalidTokenBinary = Encoding.UTF8.GetBytes(InvalidTokenString);
            }

            public string Name { get; }

            public string TokenString { get; }

            public byte[] TokenBinary { get; }

            public string InvalidTokenString { get; }

            public byte[] InvalidTokenBinary { get; }

            public override string ToString()
            {
                return Name;
            }
        }
    }
}
