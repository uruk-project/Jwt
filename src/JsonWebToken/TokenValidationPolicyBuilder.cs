﻿using JsonWebToken.Validations;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Net.Http;

namespace JsonWebToken
{
    public class TokenValidationPolicyBuilder
    {
        private const string LifetimeValidationName = "";
        public const int DefaultMaximumTokenSizeInBytes = 1024 * 1024 * 2; // 2MB
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

        public TokenValidationPolicyBuilder MaximumTokenSizeInBytes(int bytes)
        {
            if (bytes <= 0)
            {
                throw new ArgumentOutOfRangeException(nameof(bytes), ErrorMessages.FormatInvariant(ErrorMessages.MustBeGreaterThanZero, nameof(bytes), bytes));
            }

            _maximumTokenSizeInBytes = bytes;
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
            _validations.Add(new SignatureValidation(new EmptyKeyProvider(), supportUnsecure: true, null));
            return this;
        }

        public TokenValidationPolicyBuilder RequireSignature(IKeyProvider keyProvider, string algorithm = null)
        {
            _hasSignatureValidation = true;
            _validations.Add(new SignatureValidation(keyProvider, supportUnsecure: false, algorithm));
            return this;
        }

        public TokenValidationPolicyBuilder RequireSignature(string jsonWebKeyUrl, string algorithm = null, HttpMessageHandler handler = null)
        {
            RequireSignature(new JwksKeyProvider(jsonWebKeyUrl, handler), algorithm);
            return this;
        }

        public TokenValidationPolicyBuilder RequireSignature(JsonWebKey key, string algorithm = null)
        {
            return RequireSignature(new JsonWebKeySet(key), algorithm);
        }

        public TokenValidationPolicyBuilder RequireSignature(IEnumerable<JsonWebKey> keys, string algorithm = null)
        {
            return RequireSignature(new JsonWebKeySet(keys), algorithm);
        }

        public TokenValidationPolicyBuilder RequireSignature(JsonWebKeySet keySet, string algorithm = null)
        {
            return RequireSignature(new StaticKeyProvider(keySet), algorithm);
        }

        public TokenValidationPolicyBuilder RequireSignature(IEnumerable<IKeyProvider> keyProviders, string algorithm = null)
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

        public TokenValidationPolicyBuilder RequireHeader(string requiredHeader)
        {
            return AddValidation(null);
        }

        public TokenValidationPolicyBuilder AddLifetimeValidation(bool requireExpirationTime = true, int clockSkew = 300)
        {
            if (clockSkew <= 0)
            {
                throw new ArgumentOutOfRangeException(nameof(clockSkew), ErrorMessages.FormatInvariant(ErrorMessages.MustBeGreaterThanTimeSpanZero, nameof(clockSkew), clockSkew));
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
                throw new InvalidOperationException(ErrorMessages.FormatInvariant("Signature validation must be either defined by calling the method '{0}' or explicitly ignored by calling the '{1}' method.", nameof(RequireSignature), nameof(AcceptUnsecureToken)));
            }
        }

        public TokenValidationPolicy Build()
        {
            Validate();

            var policy = new TokenValidationPolicy(_validations);
            policy.MaximumTokenSizeInBytes = _maximumTokenSizeInBytes;
            return policy;
        }

        private class EmptyKeyProvider : IKeyProvider
        {
            private static readonly IReadOnlyList<JsonWebKey> Empty = Array.Empty<JsonWebKey>();

            public IReadOnlyList<JsonWebKey> GetKeys(JwtHeader header)
            {
                return Empty;
            }
        }
    }
}
