using JsonWebToken.Validations;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Net.Http;

namespace JsonWebToken
{
    public class TokenValidationPolicyBuilder
    {
        public const int DefaultMaximumTokenSizeInBytes = 1024 * 1024 * 2;
        private readonly List<IValidation> _validations = new List<IValidation>();
        private int _maximumTokenSizeInBytes = DefaultMaximumTokenSizeInBytes;
        private bool _hasSignatureValidation = false;

        public TokenValidationPolicyBuilder Clear()
        {
            _validations.Clear();
            return this;
        }

        protected TokenValidationPolicyBuilder RemoveValidation(IValidation validation)
        {
            if (validation == null)
            {
                throw new ArgumentNullException(nameof(validation));
            }

            _validations.Remove(validation);
            return this;
        }

        protected TokenValidationPolicyBuilder RemoveValidation<TValidation>() where TValidation : IValidation
        {
            _validations.RemoveAll(v => v.GetType() == typeof(TValidation));
            return this;
        }

        public TokenValidationPolicyBuilder AddValidation(IValidation validation)
        {
            if (validation == null)
            {
                throw new ArgumentNullException(nameof(validation));
            }

            _validations.Add(validation);
            return this;
        }

        public TokenValidationPolicyBuilder MaximumTokenSizeInBytes(int size)
        {
            if (size <= 0)
            {
                Errors.ThrowMustBeGreaterThanZero(nameof(size), size);
            }

            _maximumTokenSizeInBytes = size;
            return this;
        }

        public TokenValidationPolicyBuilder IgnoreSignature()
        {
            _hasSignatureValidation = true;
            return RemoveValidation<SignatureValidation>();
        }

        public TokenValidationPolicyBuilder AcceptUnsecureToken()
        {
            _hasSignatureValidation = true;
            _validations.Add(new SignatureValidation(new EmptyKeyProvider(), supportUnsecure: true, SignatureAlgorithm.None));
            return this;
        }

        public TokenValidationPolicyBuilder RequireSignature(IKeyProvider keyProvider) => RequireSignature(keyProvider, null);

        public TokenValidationPolicyBuilder RequireSignature(IKeyProvider keyProvider, SignatureAlgorithm algorithm)
        {
            _hasSignatureValidation = true;
            _validations.Add(new SignatureValidation(keyProvider, supportUnsecure: false, algorithm ?? SignatureAlgorithm.Empty));
            return this;
        }

        public TokenValidationPolicyBuilder RequireSignature(string jsonWebKeyUrl) => RequireSignature(jsonWebKeyUrl, null, null);

        public TokenValidationPolicyBuilder RequireSignature(string jsonWebKeyUrl, SignatureAlgorithm algorithm) => RequireSignature(jsonWebKeyUrl, algorithm, null);

        public TokenValidationPolicyBuilder RequireSignature(string jsonWebKeyUrl, HttpMessageHandler handler) => RequireSignature(jsonWebKeyUrl, null, handler);

        public TokenValidationPolicyBuilder RequireSignature(string jsonWebKeyUrl, SignatureAlgorithm algorithm, HttpMessageHandler handler)
        {
            RequireSignature(new JwksKeyProvider(jsonWebKeyUrl, handler), algorithm);
            return this;
        }

        public TokenValidationPolicyBuilder RequireSignature(JsonWebKey key) => RequireSignature(key, null);

        public TokenValidationPolicyBuilder RequireSignature(JsonWebKey key, SignatureAlgorithm algorithm)
        {
            return RequireSignature(new JsonWebKeySet(key), algorithm);
        }

        public TokenValidationPolicyBuilder RequireSignature(ICollection<JsonWebKey> keys) => RequireSignature(keys, null);

        public TokenValidationPolicyBuilder RequireSignature(ICollection<JsonWebKey> keys, SignatureAlgorithm algorithm)
        {
            return RequireSignature(new JsonWebKeySet(keys), algorithm);
        }

        public TokenValidationPolicyBuilder RequireSignature(JsonWebKeySet keySet) => RequireSignature(keySet, null);

        public TokenValidationPolicyBuilder RequireSignature(JsonWebKeySet keySet, SignatureAlgorithm algorithm)
        {
            return RequireSignature(new StaticKeyProvider(keySet), algorithm);
        }

        public TokenValidationPolicyBuilder RequireSignature(IEnumerable<IKeyProvider> keyProviders) => RequireSignature(keyProviders, null);

        public TokenValidationPolicyBuilder RequireSignature(IEnumerable<IKeyProvider> keyProviders, SignatureAlgorithm algorithm)
        {
            foreach (var keyProvider in keyProviders)
            {
                RequireSignature(keyProvider, algorithm);
            }

            return this;
        }

        public TokenValidationPolicyBuilder RequireClaim(string requiredClaim)
        {
            return AddValidation(new RequiredClaimValidation<JObject>(requiredClaim));
        }
        
        public TokenValidationPolicyBuilder AddLifetimeValidation(bool requireExpirationTime = true, int clockSkew = 300)
        {
            if (clockSkew <= 0)
            {
                Errors.ThrowMustBeGreaterThanTimeSpanZero(nameof(clockSkew), clockSkew);
            }

            _validations.Add(new LifetimeValidation(requireExpirationTime, clockSkew));
            return this;
        }

        public TokenValidationPolicyBuilder RequireAudience(string audience)
        {
            if (string.IsNullOrEmpty(audience))
            {
                throw new ArgumentNullException(nameof(audience));
            }

            _validations.Add(new AudienceValidation(new[] { audience }));
            return this;
        }

        public TokenValidationPolicyBuilder RequireAudience(IEnumerable<string> audiences)
        {
            if (audiences == null)
            {
                throw new ArgumentNullException(nameof(audiences));
            }

            _validations.Add(new AudienceValidation(audiences));
            return this;
        }

        public TokenValidationPolicyBuilder RequireIssuer(string issuer)
        {
            if (string.IsNullOrEmpty(issuer))
            {
                throw new ArgumentNullException(nameof(issuer));
            }

            _validations.Add(new IssuerValidation(issuer));
            return this;
        }

        public TokenValidationPolicyBuilder AddTokenReplayValidation(ITokenReplayCache tokenReplayCache)
        {
            if (tokenReplayCache == null)
            {
                throw new ArgumentNullException(nameof(tokenReplayCache));
            }

            _validations.Add(new TokenReplayValidation(tokenReplayCache));
            return this;
        }

        protected virtual void Validate()
        {
            if (!_hasSignatureValidation)
            {
                Errors.ThrowPolicyBuilderRequireSignature();
            }
        }

        public TokenValidationPolicy Build()
        {
            Validate();

            var policy = new TokenValidationPolicy(_validations)
            {
                MaximumTokenSizeInBytes = _maximumTokenSizeInBytes
            };
            return policy;
        }

        public static implicit operator TokenValidationPolicy(TokenValidationPolicyBuilder builder)
        {
            return builder?.Build();
        }

        private sealed class EmptyKeyProvider : IKeyProvider
        {
            private static readonly JsonWebKey[] Empty = Array.Empty<JsonWebKey>();

            public IReadOnlyList<JsonWebKey> GetKeys(JwtHeader header)
            {
                return Empty;
            }
        }
    }
}
