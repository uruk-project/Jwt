// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

using JsonWebToken.Internal;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Net.Http;

namespace JsonWebToken
{
    /// <summary>
    /// Represents a builder for <see cref="TokenValidationPolicy"/>.
    /// </summary>
    public sealed class TokenValidationPolicyBuilder
    {
        private const int DefaultMaximumTokenSizeInBytes = 1024 * 1024 * 2;
        private readonly Dictionary<string, ICriticalHeaderHandler> _criticalHeaderHandlers = new Dictionary<string, ICriticalHeaderHandler>();
        private readonly List<IValidator> _validators = new List<IValidator>();
        private int _maximumTokenSizeInBytes = DefaultMaximumTokenSizeInBytes;
        private bool _hasSignatureValidation = false;
        private bool _ignoreCriticalHeader;

        /// <summary>
        /// Clear the defined policies.
        /// </summary>
        /// <returns></returns>
        public TokenValidationPolicyBuilder Clear()
        {
            _validators.Clear();
            _criticalHeaderHandlers.Clear();
            return this;
        }

        private TokenValidationPolicyBuilder RemoveValidation(IValidator validator)
        {
            if (validator == null)
            {
                throw new ArgumentNullException(nameof(validator));
            }

            _validators.Remove(validator);
            return this;
        }

        private TokenValidationPolicyBuilder RemoveValidator<TValidator>() where TValidator : IValidator
        {
            _validators.RemoveAll(v => v.GetType() == typeof(TValidator));
            return this;
        }

        /// <summary>
        /// Adds a <see cref="IValidator"/>.
        /// </summary>
        /// <param name="validator"></param>
        /// <returns></returns>
        public TokenValidationPolicyBuilder AddValidator(IValidator validator)
        {
            if (validator == null)
            {
                throw new ArgumentNullException(nameof(validator));
            }

            _validators.Add(validator);
            return this;
        }

        /// <summary>
        /// Defines the maximum token size in bytes.
        /// </summary>
        /// <param name="size"></param>
        /// <returns></returns>
        public TokenValidationPolicyBuilder MaximumTokenSizeInBytes(int size)
        {
            if (size <= 0)
            {
                Errors.ThrowMustBeGreaterThanZero(nameof(size), size);
            }

            _maximumTokenSizeInBytes = size;
            return this;
        }

        /// <summary>
        /// Ignores the signature validation.
        /// </summary>
        /// <returns></returns>
        public TokenValidationPolicyBuilder IgnoreSignature()
        {
            _hasSignatureValidation = true;
            return RemoveValidator<SignatureValidator>();
        }

        /// <summary>
        /// Accepts secure token with the 'none' algorithm.
        /// </summary>
        /// <returns></returns>
        public TokenValidationPolicyBuilder AcceptUnsecureToken()
        {
            _hasSignatureValidation = true;
            RemoveValidator<SignatureValidator>();
            AddValidator(new SignatureValidator(new EmptyKeyProvider(), supportUnsecure: true, SignatureAlgorithm.None));
            return this;
        }

        /// <summary>
        /// Requires a valid signature.
        /// </summary>
        /// <param name="keyProvider"></param>
        /// <param name="algorithm"></param>
        /// <returns></returns>
        public TokenValidationPolicyBuilder RequireSignature(IKeyProvider keyProvider, SignatureAlgorithm algorithm)
        {
            _hasSignatureValidation = true;
            RemoveValidator<SignatureValidator>();
            AddValidator(new SignatureValidator(keyProvider, supportUnsecure: false, algorithm));
            return this;
        }

        /// <summary>
        /// Requires a valid signature.
        /// </summary>
        /// <param name="keyProvider"></param>
        /// <returns></returns>
        public TokenValidationPolicyBuilder RequireSignature(IKeyProvider keyProvider) => RequireSignature(keyProvider, null);

        /// <summary>
        /// Requires a valid signature.
        /// </summary>
        /// <param name="jwksUrl"></param>
        /// <returns></returns>
        public TokenValidationPolicyBuilder RequireSignature(string jwksUrl) => RequireSignature(jwksUrl, null, null);

        /// <summary>
        /// Requires a valid signature.
        /// </summary>
        /// <param name="jwksUrl"></param>
        /// <param name="algorithm"></param>
        /// <returns></returns>
        public TokenValidationPolicyBuilder RequireSignature(string jwksUrl, SignatureAlgorithm algorithm) => RequireSignature(jwksUrl, algorithm, null);

        /// <summary>
        /// Requires a valid signature.
        /// </summary>
        /// <param name="jwksUrl"></param>
        /// <param name="handler"></param>
        /// <returns></returns>
        public TokenValidationPolicyBuilder RequireSignature(string jwksUrl, HttpMessageHandler handler) => RequireSignature(jwksUrl, null, handler);

        /// <summary>
        /// Requires a valid signature.
        /// </summary>
        /// <param name="jwksUrl"></param>
        /// <param name="algorithm"></param>
        /// <param name="handler"></param>
        /// <returns></returns>
        public TokenValidationPolicyBuilder RequireSignature(string jwksUrl, SignatureAlgorithm algorithm, HttpMessageHandler handler) => RequireSignature(new JwksKeyProvider(jwksUrl, handler), algorithm);

        /// <summary>
        /// Requires a valid signature.
        /// </summary>
        /// <param name="key"></param>
        /// <returns></returns>
        public TokenValidationPolicyBuilder RequireSignature(Jwk key) => RequireSignature(key, null);

        /// <summary>
        /// Requires a valid signature.
        /// </summary>
        /// <param name="key"></param>
        /// <param name="algorithm"></param>
        /// <returns></returns>
        public TokenValidationPolicyBuilder RequireSignature(Jwk key, SignatureAlgorithm algorithm) => RequireSignature(new Jwks(key), algorithm);

        /// <summary>
        /// Requires a valid signature.
        /// </summary>
        /// <param name="keys"></param>
        /// <returns></returns>
        public TokenValidationPolicyBuilder RequireSignature(ICollection<Jwk> keys) => RequireSignature(keys, null);

        /// <summary>
        /// Requires a valid signature.
        /// </summary>
        /// <param name="keys"></param>
        /// <param name="algorithm"></param>
        /// <returns></returns>
        public TokenValidationPolicyBuilder RequireSignature(ICollection<Jwk> keys, SignatureAlgorithm algorithm) => RequireSignature(new Jwks(keys), algorithm);

        /// <summary>
        /// Requires a valid signature.
        /// </summary>
        /// <param name="keySet"></param>
        /// <returns></returns>
        public TokenValidationPolicyBuilder RequireSignature(Jwks keySet) => RequireSignature(keySet, null);

        /// <summary>
        /// Requires a valid signature.
        /// </summary>
        /// <param name="keySet"></param>
        /// <param name="algorithm"></param>
        /// <returns></returns>
        public TokenValidationPolicyBuilder RequireSignature(Jwks keySet, SignatureAlgorithm algorithm) => RequireSignature(new StaticKeyProvider(keySet), algorithm);

        /// <summary>
        /// Requires a valid signature.
        /// </summary>
        /// <param name="keyProviders"></param>
        /// <returns></returns>
        public TokenValidationPolicyBuilder RequireSignature(IEnumerable<IKeyProvider> keyProviders) => RequireSignature(keyProviders, null);

        /// <summary>
        /// Requires a valid signature.
        /// </summary>
        /// <param name="keyProviders"></param>
        /// <param name="algorithm"></param>
        /// <returns></returns>
        public TokenValidationPolicyBuilder RequireSignature(IEnumerable<IKeyProvider> keyProviders, SignatureAlgorithm algorithm)
        {
            foreach (var keyProvider in keyProviders)
            {
                RequireSignature(keyProvider, algorithm);
            }

            return this;
        }

        /// <summary>
        /// Requires the specified claim.
        /// </summary>
        /// <param name="requiredClaim"></param>
        /// <returns></returns>
        public TokenValidationPolicyBuilder RequireClaim(string requiredClaim)
        {
            return AddValidator(new RequiredClaimValidator<JObject>(requiredClaim));
        }

        /// <summary>
        /// Adds lifetime validation.
        /// </summary>
        /// <param name="requireExpirationTime"></param>
        /// <param name="clockSkew"></param>
        /// <returns></returns>
        public TokenValidationPolicyBuilder AddLifetimeValidation(bool requireExpirationTime = true, int clockSkew = 300)
        {
            if (clockSkew <= 0)
            {
                Errors.ThrowMustBeGreaterThanTimeSpanZero(nameof(clockSkew), clockSkew);
            }

            RemoveValidator<LifetimeValidator>();
            AddValidator(new LifetimeValidator(requireExpirationTime, clockSkew));
            return this;
        }

        /// <summary>
        /// Requires a specific audience.
        /// </summary>
        /// <param name="audience"></param>
        /// <returns></returns>
        public TokenValidationPolicyBuilder RequireAudience(string audience)
        {
            if (string.IsNullOrEmpty(audience))
            {
                throw new ArgumentNullException(nameof(audience));
            }

            RemoveValidator<AudienceValidator>();
            AddValidator(new AudienceValidator(new[] { audience }));
            return this;
        }

        /// <summary>
        /// Requires an audience contained in the <paramref name="audiences"/>.
        /// </summary>
        /// <param name="audiences"></param>
        /// <returns></returns>
        public TokenValidationPolicyBuilder RequireAudience(IEnumerable<string> audiences)
        {
            if (audiences == null)
            {
                throw new ArgumentNullException(nameof(audiences));
            }

            RemoveValidator<AudienceValidator>();
            AddValidator(new AudienceValidator(audiences));
            return this;
        }

        /// <summary>
        /// Requires a specific issuer.
        /// </summary>
        /// <param name="issuer"></param>
        /// <returns></returns>
        public TokenValidationPolicyBuilder RequireIssuer(string issuer)
        {
            if (string.IsNullOrEmpty(issuer))
            {
                throw new ArgumentNullException(nameof(issuer));
            }

            RemoveValidator<IssuerValidation>();
            AddValidator(new IssuerValidation(issuer));
            return this;
        }

        /// <summary>
        /// Adds token replay validation.
        /// </summary>
        /// <param name="tokenReplayCache"></param>
        /// <returns></returns>
        public TokenValidationPolicyBuilder AddTokenReplayValidation(ITokenReplayCache tokenReplayCache)
        {
            if (tokenReplayCache == null)
            {
                throw new ArgumentNullException(nameof(tokenReplayCache));
            }

            RemoveValidator<TokenReplayValidator>();
            AddValidator(new TokenReplayValidator(tokenReplayCache));
            return this;
        }

        /// <summary>
        /// Adds a critical header handler validation.
        /// </summary>
        /// <param name="header"></param>
        /// <param name="handler"></param>
        /// <returns></returns>
        public TokenValidationPolicyBuilder AddCriticalHeaderHandler(string header, ICriticalHeaderHandler handler)
        {
            _criticalHeaderHandlers.Add(header, handler);
            return this;
        }

        /// <summary>
        /// Ignore the 'crit' header.
        /// </summary>
        /// <returns></returns>
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

        /// <summary>
        /// Builds the <see cref="TokenValidationPolicy"/>.
        /// </summary>
        /// <returns></returns>
        public TokenValidationPolicy Build()
        {
            Validate();

            var policy = new TokenValidationPolicy(_validators, _criticalHeaderHandlers, _maximumTokenSizeInBytes, _ignoreCriticalHeader);
            return policy;
        }

        /// <summary>
        /// Convert the <see cref="TokenValidationPolicyBuilder"/> into a <see cref="TokenValidationPolicy"/>.
        /// </summary>
        /// <param name="builder"></param>
        public static implicit operator TokenValidationPolicy(TokenValidationPolicyBuilder builder)
        {
            return builder?.Build();
        }

        private sealed class EmptyKeyProvider : IKeyProvider
        {
            private static readonly Jwk[] Empty = Array.Empty<Jwk>();

            public IReadOnlyList<Jwk> GetKeys(JwtHeader header)
            {
                return Empty;
            }
        }
    }
}
