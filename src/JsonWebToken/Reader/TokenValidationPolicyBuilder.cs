// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;

namespace JsonWebToken
{
    /// <summary>Represents a builder for <see cref="TokenValidationPolicy"/>.</summary>
    public sealed partial class TokenValidationPolicyBuilder
    {
        private const int DefaultMaximumTokenSizeInBytes = 1024 * 1024 * 2;

        private readonly Dictionary<string, ICriticalHeaderHandler> _criticalHeaderHandlers = new Dictionary<string, ICriticalHeaderHandler>();
        private readonly Dictionary<string, SignatureValidationPolicy> _signaturePolicies = new Dictionary<string, SignatureValidationPolicy>();
        private readonly List<IValidator> _validators = new List<IValidator>();
        private readonly List<byte[]> _audiences = new List<byte[]>();
        private readonly List<byte[]> _issuers = new List<byte[]>();
        private int _maximumTokenSizeInBytes = DefaultMaximumTokenSizeInBytes;
        private bool _hasSignatureValidation = false;
        private SignatureValidationPolicy _defaultSignaturePolicy = SignatureValidationPolicy.InvalidSignature;
        private bool _ignoreCriticalHeader = false;
        private bool _ignoreNestedToken;

        private byte _control;
        private int _clockSkew;
        private IKeyProvider[]? _decryptionKeysProviders;
        private bool _headerCacheDisabled;

        /// <summary>Clear the defined policies.</summary>
        public TokenValidationPolicyBuilder Clear()
        {
            _validators.Clear();
            _criticalHeaderHandlers.Clear();
            _defaultSignaturePolicy = SignatureValidationPolicy.InvalidSignature;
            _signaturePolicies.Clear();
            _maximumTokenSizeInBytes = DefaultMaximumTokenSizeInBytes;
            _hasSignatureValidation = false;
            _ignoreNestedToken = false;
            return this;
        }

        /// <summary>Adds a <see cref="IValidator"/>.</summary>
        public TokenValidationPolicyBuilder AddValidator(IValidator validator)
        {
            if (validator == null)
            {
                throw new ArgumentNullException(nameof(validator));
            }

            _validators.Add(validator);
            return this;
        }

        /// <summary>Defines the maximum token size in bytes.</summary>
        public TokenValidationPolicyBuilder MaximumTokenSizeInBytes(int size)
        {
            if (size <= 0)
            {
                ThrowHelper.ThrowArgumentOutOfRangeException_MustBeGreaterThanZero(ExceptionArgument.size, size);
            }

            _maximumTokenSizeInBytes = size;
            return this;
        }

        /// <summary>Configure the <see cref="TokenValidationPolicy"/> based on the <paramref name="metadataUrl"/>
        /// as defined by https://tools.ietf.org/html/rfc8414 and https://openid.net/specs/openid-connect-discovery-1_0.html.
        /// The <paramref name="issuer"/> must be a valid URL.</summary>
        public TokenValidationPolicyBuilder RequireMetadataConfiguration(string issuer, SignatureAlgorithm defaultAlgorithm, string metadataUrl = "/.well-known/oauth-authorization-server",  HttpMessageHandler? handler = null)
        {
            metadataUrl = issuer + metadataUrl;
            if (!Uri.IsWellFormedUriString(metadataUrl, UriKind.Absolute))
            {
                throw new InvalidOperationException($"'{metadataUrl}' is not a valid URL.");
            }

            return RequireSignatureByDefault(issuer, new JwksKeyProvider(metadataUrl, handler, MetadataRetrievalBehavior.FromMetadataUrl), defaultAlgorithm);
        }

        /// <summary>Configure the signature behavior for a specific <paramref name="issuer"/>.</summary>
        public TokenValidationPolicyBuilder RequireSignature(string issuer, string jwksUrl, SignatureAlgorithm defaultAlgorithm, HttpMessageHandler? handler = null)
            => RequireSignatureByDefault(issuer, new JwksKeyProvider(jwksUrl, handler, MetadataRetrievalBehavior.FromJwksUrl), defaultAlgorithm);

        /// <summary>Configure the signature behavior for a specific <paramref name="issuer"/>.</summary>
        public TokenValidationPolicyBuilder RequireSignature(string issuer, Jwk key, SignatureAlgorithm defaultAlgorithm)
        {
            if (key is null)
            {
                throw new ArgumentNullException(nameof(key));
            }

            if (key.SignatureAlgorithm is null && defaultAlgorithm is null)
            {
                throw new InvalidOperationException($"The key does not define an 'alg' parameter, and the parameter {nameof(defaultAlgorithm)} is undefined. At least one algorithm must be defined.");
            }

            return RequireSignature(issuer, new Jwks(key), defaultAlgorithm);
        }

        /// <summary>Configure the signature behavior for a specific <paramref name="issuer"/>.</summary>
        public TokenValidationPolicyBuilder RequireSignature(string issuer, Jwks keys, SignatureAlgorithm defaultAlgorithm)
        {
            if (keys is null)
            {
                throw new ArgumentNullException(nameof(keys));
            }

            return RequireSignatureByDefault(issuer, new StaticKeyProvider(keys), defaultAlgorithm);
        }

        /// <summary>Configure the signature behavior for a specific <paramref name="issuer"/>.</summary>
        public TokenValidationPolicyBuilder RequireSignature(string issuer, IList<Jwk> keys, SignatureAlgorithm defaultAlgorithm)
            => RequireSignature(issuer, new Jwks(keys), defaultAlgorithm);

        /// <summary>Configure the signature behavior for a specific <paramref name="issuer"/>.</summary>
        public TokenValidationPolicyBuilder RequireSignatureByDefault(string issuer, IKeyProvider keyProvider, SignatureAlgorithm defaultAlgorithm)
        {
            if (issuer is null)
            {
                throw new ArgumentNullException(nameof(issuer));
            }

            if (keyProvider is null)
            {
                throw new ArgumentNullException(nameof(keyProvider));
            }

            if (defaultAlgorithm is null)
            {
                throw new ArgumentNullException(nameof(defaultAlgorithm));
            }

            if (defaultAlgorithm == SignatureAlgorithm.None)
            {
                throw new ArgumentException($"The algorithm 'none' is not valid with the method {nameof(RequireSignature)}. Use the method {nameof(AcceptUnsecureToken)} instead.", nameof(defaultAlgorithm));
            }

            _hasSignatureValidation = true;
            var policy = SignatureValidationPolicy.Create(keyProvider, defaultAlgorithm);
            _signaturePolicies.Add(issuer, policy);
            return this;
        }

        /// <summary>Ignores the signature validation. You should use this very carefully.</summary>
        public TokenValidationPolicyBuilder IgnoreSignature(string issuer)
        {
            if (issuer is null)
            {
                throw new ArgumentNullException(nameof(issuer));
            }

            _hasSignatureValidation = true;
            _signaturePolicies.Add(issuer, SignatureValidationPolicy.IgnoreSignature);
            return this;
        }

        /// <summary>Ignores the signature validation if no configuration is found for a specific issuer. You should use this very carefully.</summary>
        public TokenValidationPolicyBuilder IgnoreSignatureByDefault()
        {
            _hasSignatureValidation = true;
            _defaultSignaturePolicy = SignatureValidationPolicy.IgnoreSignature;
            return this;
        }

        /// <summary>Accepts secure token with the 'none' algorithm. You should use this very carefully.</summary>
        public TokenValidationPolicyBuilder AcceptUnsecureToken(string issuer)
        {
            if (issuer is null)
            {
                throw new ArgumentNullException(nameof(issuer));
            }

            _hasSignatureValidation = true;
            _signaturePolicies.Add(issuer, SignatureValidationPolicy.NoSignature);
            return this;
        }

        /// <summary>Accepts secure token with the 'none' algorithm. You should use this very carefully.</summary>
        public TokenValidationPolicyBuilder AcceptUnsecureTokenByDefault()
        {
            _hasSignatureValidation = true;
            _defaultSignaturePolicy = SignatureValidationPolicy.NoSignature;
            return this;
        }

        /// <summary>
        /// Defines the default signature validation when there is no issuer configuration.
        /// Use the method <see cref="RequireSignatureByDefault(string, IKeyProvider, SignatureAlgorithm?)"/> for linking the issuer with the signature.
        /// </summary>
        public TokenValidationPolicyBuilder RequireSignatureByDefault(IKeyProvider keyProvider, SignatureAlgorithm? algorithm)
        {
            _hasSignatureValidation = true;
            _defaultSignaturePolicy = SignatureValidationPolicy.Create(keyProvider, algorithm);
            return this;
        }

        /// <summary>
        /// Defines the default signature validation when there is no issuer configuration.
        /// Use the method <see cref="RequireSignatureByDefault(string, IKeyProvider, SignatureAlgorithm?)"/> for linking the issuer with the signature.
        /// </summary>
        public TokenValidationPolicyBuilder RequireSignatureByDefault(IKeyProvider keyProvider)
            => RequireSignatureByDefault(keyProvider, null);

        /// <summary>
        /// Defines the default signature validation when there is no issuer configuration.
        /// Use the method <see cref="RequireSignatureByDefault(string, IKeyProvider, SignatureAlgorithm?)"/> for linking the issuer with the signature.
        /// </summary>
        public TokenValidationPolicyBuilder RequireSignatureByDefault(string jwksUrl)
            => RequireSignatureByDefault(jwksUrl, null, (HttpMessageHandler?)null);

        /// <summary>
        /// Defines the default signature validation when there is no issuer configuration.
        /// Use the method <see cref="RequireSignatureByDefault(string, IKeyProvider, SignatureAlgorithm?)"/> for linking the issuer with the signature.
        /// </summary>
        public TokenValidationPolicyBuilder DefaultSignature(string jwksUrl, SignatureAlgorithm algorithm)
            => RequireSignatureByDefault(jwksUrl, algorithm, null);

        /// <summary>
        /// Defines the default signature validation when there is no issuer configuration.
        /// Use the method <see cref="RequireSignatureByDefault(string, IKeyProvider, SignatureAlgorithm?)"/> for linking the issuer with the signature.
        /// </summary>
        public TokenValidationPolicyBuilder RequireSignatureByDefault(string jwksUrl, HttpMessageHandler handler)
            => RequireSignatureByDefault(jwksUrl, null, handler);

        /// <summary>
        /// Defines the default signature validation when there is no issuer configuration.
        /// Use the method <see cref="RequireSignatureByDefault(string, IKeyProvider, SignatureAlgorithm?)"/> for linking the issuer with the signature.
        /// </summary>
        public TokenValidationPolicyBuilder RequireSignatureByDefault(string jwksUrl, SignatureAlgorithm? algorithm, HttpMessageHandler? handler)
            => RequireSignatureByDefault(new JwksKeyProvider(jwksUrl, handler), algorithm);

        /// <summary>
        /// Defines the default signature validation when there is no issuer configuration.
        /// Use the method <see cref="RequireSignatureByDefault(string, IKeyProvider, SignatureAlgorithm?)"/> for linking the issuer with the signature.
        /// </summary>
        public TokenValidationPolicyBuilder RequireSignatureByDefault(Jwk key)
        {
            if (key.SignatureAlgorithm == null)
            {
                throw new InvalidOperationException($"The key does not define an 'alg' parameter. Use the method {nameof(DefaultSignature)} with a {nameof(Jwk)} and a {nameof(SignatureAlgorithm)}.");
            }

            return RequireSignatureByDefault(key, (SignatureAlgorithm?)null);
        }

        /// <summary>
        /// Defines the default signature validation when there is no issuer configuration.
        /// Use the method <see cref="RequireSignatureByDefault(string, IKeyProvider, SignatureAlgorithm?)"/> for linking the issuer with the signature.
        /// </summary>
        public TokenValidationPolicyBuilder RequireSignatureByDefault(Jwk key, SignatureAlgorithm? algorithm)
            => RequireSignatureByDefault(new Jwks(key), algorithm);

        /// <summary>
        /// Defines the default signature validation when there is no issuer configuration.
        /// Use the method <see cref="RequireSignatureByDefault(string, IKeyProvider, SignatureAlgorithm?)"/> for linking the issuer with the signature.
        /// </summary>
        public TokenValidationPolicyBuilder RequireSignatureByDefault(Jwk key, string? algorithm)
        {
            if (algorithm is null)
            {
                throw new ArgumentNullException(nameof(algorithm));
            }

            if (!SignatureAlgorithm.TryParse(Utf8.GetBytes(algorithm), out var alg))
            {
                throw new NotSupportedException($"The algorithm '{alg}' is not supported.");
            }

            return RequireSignatureByDefault(new Jwks(key), alg);
        }

        /// <summary>
        /// Defines the default signature validation when there is no issuer configuration.
        /// Use the method <see cref="RequireSignatureByDefault(string, IKeyProvider, SignatureAlgorithm?)"/> for linking the issuer with the signature.
        /// </summary>
        public TokenValidationPolicyBuilder RequireSignatureByDefault(IList<Jwk> keys)
            => RequireSignatureByDefault(keys, null);

        /// <summary>
        /// Defines the default signature validation when there is no issuer configuration.
        /// Use the method <see cref="RequireSignatureByDefault(string, IKeyProvider, SignatureAlgorithm?)"/> for linking the issuer with the signature.
        /// </summary>
        public TokenValidationPolicyBuilder RequireSignatureByDefault(IList<Jwk> keys, SignatureAlgorithm? algorithm)
            => RequireSignatureByDefault(new Jwks(keys), algorithm);

        /// <summary>
        /// Defines the default signature validation when there is no issuer configuration.
        /// Use the method <see cref="RequireSignatureByDefault(string, IKeyProvider, SignatureAlgorithm?)"/> for linking the issuer with the signature.
        /// </summary>
        public TokenValidationPolicyBuilder RequireSignatureByDefault(Jwks keySet)
            => RequireSignatureByDefault(keySet, null);

        /// <summary>
        /// Defines the default signature validation when there is no issuer configuration.
        /// Use the method <see cref="RequireSignatureByDefault(string, IKeyProvider, SignatureAlgorithm?)"/> for linking the issuer with the signature.
        /// </summary>
        public TokenValidationPolicyBuilder RequireSignatureByDefault(Jwks keySet, SignatureAlgorithm? algorithm)
            => RequireSignatureByDefault(new StaticKeyProvider(keySet), algorithm);

        /// <summary>Requires the specified claim.</summary>
        public TokenValidationPolicyBuilder RequireClaim(string requiredClaim)
            => AddValidator(new RequiredClaimValidator(requiredClaim));

        /// <summary>Requires the specified claim.</summary>
        public TokenValidationPolicyBuilder RequireClaim(ReadOnlySpan<byte> requiredClaim)
            => RequireClaim(Utf8.GetString(requiredClaim));

        /// <summary>Enables lifetime validation. </summary>
        /// <param name="requireExpirationTime">Defines whether the 'exp' claim must be present.</param>
        /// <param name="clockSkew">Defines the time span in seconds to apply.</param>
        public TokenValidationPolicyBuilder EnableLifetimeValidation(bool requireExpirationTime = true, int clockSkew = 300)
        {
            if (clockSkew <= 0)
            {
                ThrowHelper.ThrowArgumentOutOfRangeException_MustBeGreaterThanTimeSpanZero(ExceptionArgument.clockSkew, clockSkew);
            }

            _clockSkew = clockSkew;
            _control |= TokenValidationPolicy.ExpirationTimeMask;
            if (requireExpirationTime)
            {
                _control |= TokenValidationPolicy.ExpirationTimeRequiredMask;
            }

            return this;
        }

        /// <summary>Requires a specific audience.</summary>
        public TokenValidationPolicyBuilder RequireAudience(string audience)
        {
            if (string.IsNullOrEmpty(audience))
            {
                throw new ArgumentNullException(nameof(audience));
            }

            _audiences.Add(Utf8.GetBytes(audience));
            _control |= TokenValidationPolicy.AudienceMask;
            return this;
        }

        /// <summary>Requires a least one audience contained in the <paramref name="audiences"/>.</summary>
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
                    _control |= TokenValidationPolicy.AudienceMask;
                }
            }

            return this;
        }

        /// <summary>Requires a specific issuer. This value is used if no issuer is defined by the method <see cref="RequireSignatureByDefault(string, IKeyProvider, SignatureAlgorithm?)"/>.</summary>
        public TokenValidationPolicyBuilder DefaultIssuer(string issuer)
        {
            if (string.IsNullOrEmpty(issuer))
            {
                throw new ArgumentNullException(nameof(issuer));
            }

            _issuers.Add(Utf8.GetBytes(issuer));
            _control |= TokenValidationPolicy.IssuerMask;
            return this;
        }

        /// <summary>Adds token replay validation.</summary>
        public TokenValidationPolicyBuilder EnableTokenReplayValidation(ITokenReplayCache tokenReplayCache)
        {
            if (tokenReplayCache == null)
            {
                throw new ArgumentNullException(nameof(tokenReplayCache));
            }

            AddValidator(new TokenReplayValidator(tokenReplayCache));
            return this;
        }

        /// <summary>Adds a critical header handler validation.</summary>
        public TokenValidationPolicyBuilder AddCriticalHeaderHandler(string header, ICriticalHeaderHandler handler)
        {
            _criticalHeaderHandlers.Add(header, handler);
            return this;
        }

        /// <summary>Ignore the 'crit' header if present. <seealso cref="AddCriticalHeaderHandler(string, ICriticalHeaderHandler)"/></summary>
        public TokenValidationPolicyBuilder IgnoreCriticalHeader()
        {
            _ignoreCriticalHeader = true;
            return this;
        }

        /// <summary>Requires a specific algorithm.</summary>
        public TokenValidationPolicyBuilder RequireAlgorithm(string algorithm)
        {
            if (string.IsNullOrEmpty(algorithm))
            {
                throw new ArgumentNullException(nameof(algorithm));
            }

            AddValidator(new AlgorithmValidation(algorithm));
            return this;
        }

        /// <summary>Ignores the nested token. If a JWE contains a nested JWS, the nested token will be leaved as uncompress and decrypted binary data.</summary>
        public TokenValidationPolicyBuilder IgnoreNestedToken()
        {
            _ignoreNestedToken = true;
            return this;
        }

        /// <summary>Defines the keys providers used to decrypt the tokens.</summary>
        public TokenValidationPolicyBuilder WithDecryptionKeys(ICollection<IKeyProvider> decryptionKeyProviders)
        {
            if (decryptionKeyProviders is null)
            {
                ThrowHelper.ThrowArgumentNullException(ExceptionArgument.decryptionKeyProviders);
            }

            _decryptionKeysProviders = decryptionKeyProviders.Where(p => p != null).ToArray();
            return this;
        }

        /// <summary>Defines the keys used to decrypt the tokens.</summary>
        public TokenValidationPolicyBuilder WithDecryptionKeys(params Jwk[] decryptionKeys)
            => WithDecryptionKeys(new Jwks(decryptionKeys));

        /// <summary>Defines the keys providers used to decrypt the tokens.</summary>
        public TokenValidationPolicyBuilder WithDecryptionKeys(IKeyProvider decryptionKeyProvider)
            => WithDecryptionKeys(new[] { decryptionKeyProvider });

        /// <summary>Defines the <see cref="Jwks"/> used to decrypt the tokens.</summary>
        public TokenValidationPolicyBuilder WithDecryptionKeys(Jwks decryptionKeys)
            => WithDecryptionKeys(new StaticKeyProvider(decryptionKeys));

        /// <summary>Defines the <see cref="Jwk"/> used to decrypt the tokens.</summary>
        public TokenValidationPolicyBuilder WithDecryptionKey(Jwk encryptionKey)
             => WithDecryptionKeys(new Jwks(encryptionKey));

        /// <summary>Disable the header cache. This may be useful if the headers are complex.</summary>
        public TokenValidationPolicyBuilder DisableHeaderCache()
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

        /// <summary>Builds the <see cref="TokenValidationPolicy"/>.</summary>
        public TokenValidationPolicy Build()
        {
            Validate();

            SignatureValidationPolicy signaturePolicy;
            if (_signaturePolicies.Count == 0)
            {
                signaturePolicy = _defaultSignaturePolicy;
            }
            else if(_signaturePolicies.Count == 1)
            {
                var first = _signaturePolicies.First();
                signaturePolicy = SignatureValidationPolicy.Create(first.Key, first.Value);
            }
            else
            {
                signaturePolicy = SignatureValidationPolicy.Create(_signaturePolicies, _defaultSignaturePolicy);
            }

            var policy = new TokenValidationPolicy(
                validators: _validators.ToArray(),
                criticalHandlers: _criticalHeaderHandlers,
                maximumTokenSizeInBytes: _maximumTokenSizeInBytes,
                ignoreCriticalHeader: _ignoreCriticalHeader,
                ignoreNestedToken: _ignoreNestedToken,
                headerCacheDisabled: _headerCacheDisabled,
                signaturePolicy: signaturePolicy,
                encryptionKeyProviders: _decryptionKeysProviders,
                issuers: _issuers.ToArray(),
                audiences: _audiences.ToArray(),
                clockSkew: _clockSkew,
                control: _control);
            return policy;
        }

        private sealed class EmptyKeyProvider : IKeyProvider
        {
            private static readonly Jwk[] Empty = Array.Empty<Jwk>();

            public Jwk[] GetKeys(JwtHeaderDocument header)
                => Empty;
        }
    }
}
