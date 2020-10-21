// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using JsonWebToken.Internal;

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
        private SignatureValidationPolicy? _signatureValidation = SignatureValidationPolicy.IgnoreSignature;
        private bool _ignoreCriticalHeader = false;
        private bool _ignoreNestedToken;

        private byte _control;
        private byte[]? _issuer;
        private int _clockSkew;
        private IKeyProvider[] _decryptionKeysProviders;
        private bool _headerCacheDisabled;
        private readonly List<byte[]> _audiences = new List<byte[]>();

        /// <summary>
        /// Clear the defined policies.
        /// </summary>
        /// <returns></returns>
        public TokenValidationPolicyBuilder Clear()
        {
            _validators.Clear();
            _criticalHeaderHandlers.Clear();
            _signatureValidation = SignatureValidationPolicy.IgnoreSignature;
            _maximumTokenSizeInBytes = DefaultMaximumTokenSizeInBytes;
            _hasSignatureValidation = false;
            _ignoreNestedToken = false;
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
                ThrowHelper.ThrowArgumentOutOfRangeException_MustBeGreaterThanZero(ExceptionArgument.size, size);
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
            _signatureValidation = SignatureValidationPolicy.IgnoreSignature;
            return this;
        }

        /// <summary>
        /// Accepts secure token with the 'none' algorithm.
        /// </summary>
        /// <returns></returns>
        public TokenValidationPolicyBuilder AcceptUnsecureToken()
        {
            _hasSignatureValidation = true;
            _signatureValidation = SignatureValidationPolicy.NoSignature;
            return this;
        }

        /// <summary>
        /// Requires a valid signature.
        /// </summary>
        /// <param name="keyProvider"></param>
        /// <param name="algorithm"></param>
        /// <returns></returns>
        public TokenValidationPolicyBuilder RequireSignature(IKeyProvider keyProvider, SignatureAlgorithm? algorithm)
        {
            _hasSignatureValidation = true;
            _signatureValidation = SignatureValidationPolicy.Create(keyProvider, algorithm);
            return this;
        }

        /// <summary>
        /// Requires a valid signature.
        /// </summary>
        /// <param name="keyProvider"></param>
        /// <returns></returns>
        public TokenValidationPolicyBuilder RequireSignature(IKeyProvider keyProvider)
            => RequireSignature(keyProvider, null);

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
        public TokenValidationPolicyBuilder RequireSignature(string jwksUrl, SignatureAlgorithm algorithm)
            => RequireSignature(jwksUrl, algorithm, null);

        /// <summary>
        /// Requires a valid signature.
        /// </summary>
        /// <param name="jwksUrl"></param>
        /// <param name="handler"></param>
        /// <returns></returns>
        public TokenValidationPolicyBuilder RequireSignature(string jwksUrl, HttpMessageHandler handler)
            => RequireSignature(jwksUrl, null, handler);

        /// <summary>
        /// Requires a valid signature.
        /// </summary>
        /// <param name="jwksUrl"></param>
        /// <param name="algorithm"></param>
        /// <param name="handler"></param>
        /// <returns></returns>
        public TokenValidationPolicyBuilder RequireSignature(string jwksUrl, SignatureAlgorithm? algorithm, HttpMessageHandler? handler)
            => RequireSignature(new JwksKeyProvider(jwksUrl, handler), algorithm);

        /// <summary>
        /// Requires a valid signature.
        /// </summary>
        /// <param name="key"></param>
        /// <returns></returns>
        public TokenValidationPolicyBuilder RequireSignature(Jwk key)
        {
            if (key.SignatureAlgorithm == null)
            {
                throw new InvalidOperationException($"The key does not define an 'alg' parameter. Use the method {nameof(RequireSignature)} with a {nameof(Jwk)} and a {nameof(SignatureAlgorithm)}.");
            }

            return RequireSignature(key, null);
        }

        /// <summary>
        /// Requires a valid signature.
        /// </summary>
        /// <param name="key"></param>
        /// <param name="algorithm"></param>
        /// <returns></returns>
        public TokenValidationPolicyBuilder RequireSignature(Jwk key, SignatureAlgorithm? algorithm) => RequireSignature(new Jwks(key), algorithm);

        /// <summary>
        /// Requires a valid signature.
        /// </summary>
        /// <param name="keys"></param>
        /// <returns></returns>
        public TokenValidationPolicyBuilder RequireSignature(IList<Jwk> keys) => RequireSignature(keys, null);

        /// <summary>
        /// Requires a valid signature.
        /// </summary>
        /// <param name="keys"></param>
        /// <param name="algorithm"></param>
        /// <returns></returns>
        public TokenValidationPolicyBuilder RequireSignature(IList<Jwk> keys, SignatureAlgorithm? algorithm) => RequireSignature(new Jwks(keys), algorithm);

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
        public TokenValidationPolicyBuilder RequireSignature(Jwks keySet, SignatureAlgorithm? algorithm) => RequireSignature(new StaticKeyProvider(keySet), algorithm);

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
        public TokenValidationPolicyBuilder RequireSignature(IEnumerable<IKeyProvider> keyProviders, SignatureAlgorithm? algorithm)
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
            return AddValidator(new RequiredClaimValidator(requiredClaim));
        }

        /// <summary>
        /// Requires the specified claim.
        /// </summary>
        /// <param name="requiredClaim"></param>
        /// <returns></returns>
        public TokenValidationPolicyBuilder RequireClaim(ReadOnlySpan<byte> requiredClaim)
        {
            return RequireClaim(Utf8.GetString(requiredClaim));
        }

        /// <summary>
        /// Adds lifetime validation.
        /// </summary>
        /// <param name="requireExpirationTime"></param>
        /// <param name="clockSkew"></param>
        /// <returns></returns>
        public TokenValidationPolicyBuilder EnableLifetimeValidation(bool requireExpirationTime = true, int clockSkew = 300)
        {
            if (clockSkew <= 0)
            {
                ThrowHelper.ThrowArgumentOutOfRangeException_MustBeGreaterThanTimeSpanZero(ExceptionArgument.clockSkew, clockSkew);
            }

            _clockSkew = clockSkew;
            _control |= TokenValidationPolicy.ExpirationTimeFlag;
            if (requireExpirationTime)
            {
                _control |= TokenValidationPolicy.ExpirationTimeRequiredFlag;
            }

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

            _audiences.Add(Utf8.GetBytes(audience));
            _control |= TokenValidationPolicy.AudienceFlag;
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

            foreach (var audience in audiences)
            {
                if (audience != null)
                {
                    _audiences.Add(Utf8.GetBytes(audience));
                    _control |= TokenValidationPolicy.AudienceFlag;
                }
            }

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

            _issuer = Utf8.GetBytes(issuer);
            _control |= TokenValidationPolicy.IssuerFlag;
            return this;
        }

        /// <summary>
        /// Adds token replay validation.
        /// </summary>
        /// <param name="tokenReplayCache"></param>
        /// <returns></returns>
        public TokenValidationPolicyBuilder EnableTokenReplayValidation(ITokenReplayCache tokenReplayCache)
        {
            if (tokenReplayCache == null)
            {
                throw new ArgumentNullException(nameof(tokenReplayCache));
            }

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
        /// Ignore the 'crit' header if present.
        /// </summary>
        /// <returns></returns>
        public TokenValidationPolicyBuilder IgnoreCriticalHeader()
        {
            _ignoreCriticalHeader = true;
            return this;
        }

        /// <summary>
        /// Requires a specific algorithm.
        /// </summary>
        /// <param name="algorithm"></param>
        /// <returns></returns>
        public TokenValidationPolicyBuilder RequireAlgorithm(string algorithm)
        {
            if (string.IsNullOrEmpty(algorithm))
            {
                throw new ArgumentNullException(nameof(algorithm));
            }

            AddValidator(new AlgorithmValidation(algorithm));
            return this;
        }

        /// <summary>
        /// Ignores the nested token. If present like a JWE containing a nested JWS, the nested token will be leaved as uncompress and decrypted binary data.
        /// </summary>
        /// <returns></returns>
        public TokenValidationPolicyBuilder IgnoreNestedToken()
        {
            _ignoreNestedToken = true;
            return this;
        }

        /// <summary>
        /// Defines the keys providers used to decrypt the tokens.
        /// </summary>
        /// <returns></returns>
        public TokenValidationPolicyBuilder WithDecryptionKeys(ICollection<IKeyProvider> decryptionKeyProviders)
        {
            if (decryptionKeyProviders is null)
            {
                ThrowHelper.ThrowArgumentNullException(ExceptionArgument.decryptionKeyProviders);
            }

            _decryptionKeysProviders = decryptionKeyProviders.Where(p => p != null).ToArray();
            return this;
        }

        /// <summary>
        /// Defines the keys used to decrypt the tokens.
        /// </summary>
        /// <returns></returns>
        public TokenValidationPolicyBuilder WithDecryptionKeys(params Jwk[] decryptionKeys)
            => WithDecryptionKeys(new Jwks(decryptionKeys));

        /// <summary>
        /// Defines the keys providers used to decrypt the tokens.
        /// </summary>
        /// <returns></returns>
        public TokenValidationPolicyBuilder WithDecryptionKeys(IKeyProvider decryptionKeyProvider)
            => WithDecryptionKeys(new[] { decryptionKeyProvider });

        /// <summary>
        /// Defines the keys used to decrypt the tokens.
        /// </summary>
        /// <returns></returns>
        public TokenValidationPolicyBuilder WithDecryptionKeys(Jwks decryptionKeys)
            => WithDecryptionKeys(new StaticKeyProvider(decryptionKeys));

        /// <summary>
        /// Defines the keys providers used to decrypt the tokens.
        /// </summary>
        /// <returns></returns>
        public TokenValidationPolicyBuilder WithDecryptionKeys(Jwk encryptionKey)
             => WithDecryptionKeys(new Jwks(encryptionKey));

        /// <summary>
        /// Defines the keys providers used to decrypt the tokens.
        /// </summary>
        /// <returns></returns>
        public TokenValidationPolicyBuilder DisabledHeaderCache()
        {
            _headerCacheDisabled = true;
            return this;
        }

        private void Validate()
        {
            if (!_hasSignatureValidation)
            {
                ThrowHelper.ThrowInvalidOperationException_PolicyBuilderRequireSignature();
            }
        }

        /// <summary>
        /// Builds the <see cref="TokenValidationPolicy"/>.
        /// </summary>
        /// <returns></returns>
        public TokenValidationPolicy Build()
        {
            Validate();

            var policy = new TokenValidationPolicy(
                validators: _validators.ToArray(),
                criticalHandlers: _criticalHeaderHandlers,
                maximumTokenSizeInBytes: _maximumTokenSizeInBytes,
                ignoreCriticalHeader: _ignoreCriticalHeader,
                ignoreNestedToken: _ignoreNestedToken,
                headerCacheDisabled: _headerCacheDisabled,
                signatureValidation: _signatureValidation,
                encryptionKeyProviders: _decryptionKeysProviders,
                issuer: _issuer,
                audiences: _audiences.ToArray(),
                clockSkew: _clockSkew,
                control: _control);
            return policy;
        }

        /// <summary>
        /// Convert the <see cref="TokenValidationPolicyBuilder"/> into a <see cref="TokenValidationPolicy"/>.
        /// </summary>
        /// <param name="builder"></param>
        public static implicit operator TokenValidationPolicy?(TokenValidationPolicyBuilder builder)
        {
            return builder?.Build();
        }

        private sealed class EmptyKeyProvider : IKeyProvider
        {
            private static readonly Jwk[] Empty = Array.Empty<Jwk>();

            public Jwk[] GetKeys(JwtHeader header)
            {
                return Empty;
            }

            public Jwk[] GetKeys(JwtHeaderDocument header)
            {
                return Empty;
            }
        }
    }
}
