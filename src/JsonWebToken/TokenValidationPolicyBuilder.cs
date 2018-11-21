// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

using JsonWebToken.Internal;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Net.Http;

namespace JsonWebToken
{
    public sealed class TokenValidationPolicyBuilder
    {
        private readonly IDictionary<string, ICriticalHeaderHandler> _criticalHeaderHandlers = new Dictionary<string, ICriticalHeaderHandler>();
        private readonly List<IValidator> _validators = new List<IValidator>();
        private int _maximumTokenSizeInBytes = TokenValidationPolicy.DefaultMaximumTokenSizeInBytes;
        private bool _hasSignatureValidation = false;
        private bool _ignoreCriticalHeader;

        public TokenValidationPolicyBuilder Clear()
        {
            _validators.Clear();
            _criticalHeaderHandlers.Clear();
            return this;
        }

        protected TokenValidationPolicyBuilder RemoveValidation(IValidator validator)
        {
            if (validator == null)
            {
                throw new ArgumentNullException(nameof(validator));
            }

            _validators.Remove(validator);
            return this;
        }

        protected TokenValidationPolicyBuilder RemoveValidator<TValidator>() where TValidator : IValidator
        {
            _validators.RemoveAll(v => v.GetType() == typeof(TValidator));
            return this;
        }

        public TokenValidationPolicyBuilder AddValidator(IValidator validator)
        {
            if (validator == null)
            {
                throw new ArgumentNullException(nameof(validator));
            }

            _validators.Add(validator);
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
            return RemoveValidator<SignatureValidator>();
        }

        public TokenValidationPolicyBuilder AcceptUnsecureToken()
        {
            _hasSignatureValidation = true;
            _validators.Add(new SignatureValidator(new EmptyKeyProvider(), supportUnsecure: true, SignatureAlgorithm.None));
            return this;
        }

        public TokenValidationPolicyBuilder RequireSignature(IKeyProvider keyProvider) => RequireSignature(keyProvider, null);

        public TokenValidationPolicyBuilder RequireSignature(IKeyProvider keyProvider, SignatureAlgorithm algorithm)
        {
            _hasSignatureValidation = true;
            _validators.Add(new SignatureValidator(keyProvider, supportUnsecure: false, algorithm ?? SignatureAlgorithm.Empty));
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
            return AddValidator(new RequiredClaimValidator<JObject>(requiredClaim));
        }

        public TokenValidationPolicyBuilder AddLifetimeValidation(bool requireExpirationTime = true, int clockSkew = 300)
        {
            if (clockSkew <= 0)
            {
                Errors.ThrowMustBeGreaterThanTimeSpanZero(nameof(clockSkew), clockSkew);
            }

            _validators.Add(new LifetimeValidator(requireExpirationTime, clockSkew));
            return this;
        }

        public TokenValidationPolicyBuilder RequireAudience(string audience)
        {
            if (string.IsNullOrEmpty(audience))
            {
                throw new ArgumentNullException(nameof(audience));
            }

            _validators.Add(new AudienceValidator(new[] { audience }));
            return this;
        }

        public TokenValidationPolicyBuilder RequireAudience(IEnumerable<string> audiences)
        {
            if (audiences == null)
            {
                throw new ArgumentNullException(nameof(audiences));
            }

            _validators.Add(new AudienceValidator(audiences));
            return this;
        }

        public TokenValidationPolicyBuilder RequireIssuer(string issuer)
        {
            if (string.IsNullOrEmpty(issuer))
            {
                throw new ArgumentNullException(nameof(issuer));
            }

            _validators.Add(new IssuerValidation(issuer));
            return this;
        }

        public TokenValidationPolicyBuilder AddTokenReplayValidation(ITokenReplayCache tokenReplayCache)
        {
            if (tokenReplayCache == null)
            {
                throw new ArgumentNullException(nameof(tokenReplayCache));
            }

            _validators.Add(new TokenReplayValidator(tokenReplayCache));
            return this;
        }

        public TokenValidationPolicyBuilder AddCriticalHeaderHandler(string header, ICriticalHeaderHandler handler)
        {
            _criticalHeaderHandlers.Add(header, handler);
            return this;
        }

        public TokenValidationPolicyBuilder IgnoreCriticalHeader()
        {
            _ignoreCriticalHeader = true;
            return this;
        }

        private void Validate()
        {
            if (!_hasSignatureValidation)
            {
                Errors.ThrowPolicyBuilderRequireSignature();
            }
        }

        public TokenValidationPolicy Build()
        {
            Validate();

            var policy = new TokenValidationPolicy(_validators, _criticalHeaderHandlers, _maximumTokenSizeInBytes, _ignoreCriticalHeader)
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
