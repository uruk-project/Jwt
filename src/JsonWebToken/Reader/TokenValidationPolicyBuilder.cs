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
        private readonly Dictionary<string, SignatureValidationPolicy> _signaturePolicies = new Dictionary<string, SignatureValidationPolicy>();
        private readonly List<IValidator> _validators = new List<IValidator>();
        private readonly List<byte[]> _audiences = new List<byte[]>();
        private readonly List<byte[]> _issuers = new List<byte[]>();
        private int _maximumTokenSizeInBytes = DefaultMaximumTokenSizeInBytes;
        private bool _hasSignatureValidation = false;
        private SignatureValidationPolicy _defaultSignaturePolicy = SignatureValidationPolicy.IgnoreSignature;
        private bool _ignoreCriticalHeader = false;
        private bool _ignoreNestedToken;

        private byte _control;
        private int _clockSkew;
        private IKeyProvider[]? _decryptionKeysProviders;
        private bool _headerCacheDisabled;

        /// <summary>
        /// Clear the defined policies.
        /// </summary>
        /// <returns></returns>
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
        /// Configure the <see cref="TokenValidationPolicy"/> based on the <paramref name="metadataUrl"/> as defined by https://tools.ietf.org/html/rfc8414 and https://openid.net/specs/openid-connect-discovery-1_0.html.
        /// The <paramref name="issuer"/> must be a valid URL.
        /// </summary>
        /// <param name="issuer"></param>
        /// <param name="metadataUrl"></param>
        /// <param name="defaultAlgorithm"></param>
        /// <param name="handler"></param>
        /// <returns></returns>
        public TokenValidationPolicyBuilder RequireMetadataConfiguration(string issuer, SignatureAlgorithm defaultAlgorithm, string metadataUrl = "/.well-known/oauth-authorization-server",  HttpMessageHandler? handler = null)
        {
            metadataUrl = issuer + metadataUrl;
            if (!Uri.IsWellFormedUriString(metadataUrl, UriKind.Absolute))
            {
                throw new InvalidOperationException($"'{metadataUrl}' is not a valid URL.");
            }

            return RequireIssuer(issuer, new JwksKeyProvider(metadataUrl, handler, MetadataRetrievalBehavior.FromMetadataUrl), defaultAlgorithm);
        }

        /// <summary>
        /// Configure the signature behavior for a specific <paramref name="issuer"/>.
        /// </summary>
        /// <param name="issuer"></param>
        /// <param name="jwksUrl"></param>
        /// <param name="defaultAlgorithm"></param>
        /// <param name="handler"></param>
        /// <returns></returns>
        public TokenValidationPolicyBuilder RequireIssuer(string issuer, string jwksUrl, SignatureAlgorithm defaultAlgorithm, HttpMessageHandler? handler = null)
            => RequireIssuer(issuer, new JwksKeyProvider(jwksUrl, handler, MetadataRetrievalBehavior.FromJwksUrl), defaultAlgorithm);

        /// <summary>
        /// Configure the signature behavior for a specific <paramref name="issuer"/>.
        /// </summary>
        /// <param name="issuer"></param>
        /// <param name="key"></param>
        /// <param name="defaultAlgorithm"></param>
        /// <returns></returns>
        public TokenValidationPolicyBuilder RequireIssuer(string issuer, Jwk key, SignatureAlgorithm defaultAlgorithm)
        {
            if (key is null)
            {
                throw new ArgumentNullException(nameof(key));
            }

            if (key.SignatureAlgorithm is null && defaultAlgorithm is null)
            {
                throw new InvalidOperationException($"The key does not define an 'alg' parameter, and the parameter {nameof(defaultAlgorithm)} is undefined. At least one algorithm must be defined.");
            }

            return RequireIssuer(issuer, new Jwks(key), defaultAlgorithm);
        }

        /// <summary>
        /// Configure the signature behavior for a specific <paramref name="issuer"/>.
        /// </summary>
        /// <param name="issuer"></param>
        /// <param name="keys"></param>
        /// <param name="defaultAlgorithm"></param>
        /// <returns></returns>
        public TokenValidationPolicyBuilder RequireIssuer(string issuer, Jwks keys, SignatureAlgorithm defaultAlgorithm)
        {
            if (keys is null)
            {
                throw new ArgumentNullException(nameof(keys));
            }

            return RequireIssuer(issuer, new StaticKeyProvider(keys), defaultAlgorithm);
        }

        /// <summary>
        /// Configure the signature behavior for a specific <paramref name="issuer"/>.
        /// </summary>
        /// <param name="issuer"></param>
        /// <param name="keys"></param>
        /// <param name="defaultAlgorithm"></param>
        /// <returns></returns>
        public TokenValidationPolicyBuilder RequireIssuer(string issuer, IList<Jwk> keys, SignatureAlgorithm defaultAlgorithm)
            => RequireIssuer(issuer, new Jwks(keys), defaultAlgorithm);

        /// <summary>
        /// Configure the signature behavior for a specific <paramref name="issuer"/>.
        /// </summary>
        /// <param name="issuer"></param>
        /// <param name="keyProvider"></param>
        /// <param name="defaultAlgorithm"></param>
        /// <returns></returns>
        public TokenValidationPolicyBuilder RequireIssuer(string issuer, IKeyProvider keyProvider, SignatureAlgorithm defaultAlgorithm)
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
                throw new ArgumentException($"The algorithm 'none' is not valid with the method {nameof(RequireIssuer)}. Use the method {nameof(AcceptUnsecureToken)} instead.", nameof(defaultAlgorithm));
            }

            _hasSignatureValidation = true;
            var policy = SignatureValidationPolicy.Create(keyProvider, defaultAlgorithm);
            _signaturePolicies.Add(issuer, policy);
            return this;
        }

        /// <summary>
        /// Ignores the signature validation. You should use this very carefully.
        /// </summary>
        /// <param name="issuer"></param>
        /// <returns></returns>
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

        /// <summary>
        /// Ignores the signature validation if no configuration is found for a specific issuer. You should use this very carefully.
        /// </summary>
        /// <returns></returns>
        public TokenValidationPolicyBuilder IgnoreSignatureByDefault()
        {
            _hasSignatureValidation = true;
            _defaultSignaturePolicy = SignatureValidationPolicy.IgnoreSignature;
            return this;
        }

        /// <summary>
        /// Accepts secure token with the 'none' algorithm. You should use this very carefully.
        /// </summary>
        /// <param name="issuer"></param>
        /// <returns></returns>
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

        /// <summary>
        /// Accepts secure token with the 'none' algorithm. You should use this very carefully.
        /// </summary>
        /// <returns></returns>
        public TokenValidationPolicyBuilder AcceptUnsecureTokenByDefault()
        {
            _hasSignatureValidation = true;
            _defaultSignaturePolicy = SignatureValidationPolicy.NoSignature;
            return this;
        }

        /// <summary>
        /// Defines the default signature validation when there is no issuer configuration.
        /// Use the method <see cref="RequireIssuer(string, IKeyProvider, SignatureAlgorithm?)"/> for linking the issuer with the signature.
        /// </summary>
        /// <param name="keyProvider"></param>
        /// <param name="algorithm"></param>
        /// <returns></returns>
        public TokenValidationPolicyBuilder DefaultSignature(IKeyProvider keyProvider, SignatureAlgorithm? algorithm)
        {
            _hasSignatureValidation = true;
            _defaultSignaturePolicy = SignatureValidationPolicy.Create(keyProvider, algorithm);
            return this;
        }

        /// <summary>
        /// Defines the default signature validation when there is no issuer configuration.
        /// Use the method <see cref="RequireIssuer(string, IKeyProvider, SignatureAlgorithm?)"/> for linking the issuer with the signature.
        /// </summary>
        /// <param name="keyProvider"></param>
        /// <returns></returns>
        public TokenValidationPolicyBuilder DefaultSignature(IKeyProvider keyProvider)
            => DefaultSignature(keyProvider, null);

        /// <summary>
        /// Defines the default signature validation when there is no issuer configuration.
        /// Use the method <see cref="RequireIssuer(string, IKeyProvider, SignatureAlgorithm?)"/> for linking the issuer with the signature.
        /// </summary>
        /// <param name="jwksUrl"></param>
        /// <returns></returns>
        public TokenValidationPolicyBuilder DefaultSignature(string jwksUrl)
            => DefaultSignature(jwksUrl, null, null);

        /// <summary>
        /// Defines the default signature validation when there is no issuer configuration.
        /// Use the method <see cref="RequireIssuer(string, IKeyProvider, SignatureAlgorithm?)"/> for linking the issuer with the signature.
        /// </summary>
        /// <param name="jwksUrl"></param>
        /// <param name="algorithm"></param>
        /// <returns></returns>
        public TokenValidationPolicyBuilder DefaultSignature(string jwksUrl, SignatureAlgorithm algorithm)
            => DefaultSignature(jwksUrl, algorithm, null);

        /// <summary>
        /// Defines the default signature validation when there is no issuer configuration.
        /// Use the method <see cref="RequireIssuer(string, IKeyProvider, SignatureAlgorithm?)"/> for linking the issuer with the signature.
        /// </summary>
        /// <param name="jwksUrl"></param>
        /// <param name="handler"></param>
        /// <returns></returns>
        public TokenValidationPolicyBuilder DefaultSignature(string jwksUrl, HttpMessageHandler handler)
            => DefaultSignature(jwksUrl, null, handler);

        /// <summary>
        /// Defines the default signature validation when there is no issuer configuration.
        /// Use the method <see cref="RequireIssuer(string, IKeyProvider, SignatureAlgorithm?)"/> for linking the issuer with the signature.
        /// </summary>
        /// <param name="jwksUrl"></param>
        /// <param name="algorithm"></param>
        /// <param name="handler"></param>
        /// <returns></returns>
        public TokenValidationPolicyBuilder DefaultSignature(string jwksUrl, SignatureAlgorithm? algorithm, HttpMessageHandler? handler)
            => DefaultSignature(new JwksKeyProvider(jwksUrl, handler), algorithm);

        /// <summary>
        /// Defines the default signature validation when there is no issuer configuration.
        /// Use the method <see cref="RequireIssuer(string, IKeyProvider, SignatureAlgorithm?)"/> for linking the issuer with the signature.
        /// </summary>
        /// <param name="key"></param>
        /// <returns></returns>
        public TokenValidationPolicyBuilder DefaultSignature(Jwk key)
        {
            if (key.SignatureAlgorithm == null)
            {
                throw new InvalidOperationException($"The key does not define an 'alg' parameter. Use the method {nameof(DefaultSignature)} with a {nameof(Jwk)} and a {nameof(SignatureAlgorithm)}.");
            }

            return DefaultSignature(key, (SignatureAlgorithm?)null);
        }

        /// <summary>
        /// Defines the default signature validation when there is no issuer configuration.
        /// Use the method <see cref="RequireIssuer(string, IKeyProvider, SignatureAlgorithm?)"/> for linking the issuer with the signature.
        /// </summary>
        /// <param name="key"></param>
        /// <param name="algorithm"></param>
        /// <returns></returns>
        public TokenValidationPolicyBuilder DefaultSignature(Jwk key, SignatureAlgorithm? algorithm)
            => DefaultSignature(new Jwks(key), algorithm);

        /// <summary>
        /// Defines the default signature validation when there is no issuer configuration.
        /// Use the method <see cref="RequireIssuer(string, IKeyProvider, SignatureAlgorithm?)"/> for linking the issuer with the signature.
        /// </summary>
        /// <param name="key"></param>
        /// <param name="algorithm"></param>
        /// <returns></returns>
        public TokenValidationPolicyBuilder DefaultSignature(Jwk key, string? algorithm)
        {
            if (algorithm is null)
            {
                throw new ArgumentNullException(nameof(algorithm));
            }

            if (!SignatureAlgorithm.TryParse(Utf8.GetBytes(algorithm), out var alg))
            {
                throw new NotSupportedException($"The algorithm '{alg}' is not supported.");
            }

            return DefaultSignature(new Jwks(key), alg);
        }

        /// <summary>
        /// Defines the default signature validation when there is no issuer configuration.
        /// Use the method <see cref="RequireIssuer(string, IKeyProvider, SignatureAlgorithm?)"/> for linking the issuer with the signature.
        /// </summary>
        /// <param name="keys"></param>
        /// <returns></returns>
        public TokenValidationPolicyBuilder DefaultSignature(IList<Jwk> keys)
            => DefaultSignature(keys, null);

        /// <summary>
        /// Defines the default signature validation when there is no issuer configuration.
        /// Use the method <see cref="RequireIssuer(string, IKeyProvider, SignatureAlgorithm?)"/> for linking the issuer with the signature.
        /// </summary>
        /// <param name="keys"></param>
        /// <param name="algorithm"></param>
        /// <returns></returns>
        public TokenValidationPolicyBuilder DefaultSignature(IList<Jwk> keys, SignatureAlgorithm? algorithm)
            => DefaultSignature(new Jwks(keys), algorithm);

        /// <summary>
        /// Defines the default signature validation when there is no issuer configuration.
        /// Use the method <see cref="RequireIssuer(string, IKeyProvider, SignatureAlgorithm?)"/> for linking the issuer with the signature.
        /// </summary>
        /// <param name="keySet"></param>
        /// <returns></returns>
        public TokenValidationPolicyBuilder DefaultSignature(Jwks keySet)
            => DefaultSignature(keySet, null);

        /// <summary>
        /// Defines the default signature validation when there is no issuer configuration.
        /// Use the method <see cref="RequireIssuer(string, IKeyProvider, SignatureAlgorithm?)"/> for linking the issuer with the signature.
        /// </summary>
        /// <param name="keySet"></param>
        /// <param name="algorithm"></param>
        /// <returns></returns>
        public TokenValidationPolicyBuilder DefaultSignature(Jwks keySet, SignatureAlgorithm? algorithm)
            => DefaultSignature(new StaticKeyProvider(keySet), algorithm);

        /// <summary>
        /// Requires the specified claim.
        /// </summary>
        /// <param name="requiredClaim"></param>
        /// <returns></returns>
        public TokenValidationPolicyBuilder RequireClaim(string requiredClaim)
            => AddValidator(new RequiredClaimValidator(requiredClaim));

        /// <summary>
        /// Requires the specified claim.
        /// </summary>
        /// <param name="requiredClaim"></param>
        /// <returns></returns>
        public TokenValidationPolicyBuilder RequireClaim(ReadOnlySpan<byte> requiredClaim)
            => RequireClaim(Utf8.GetString(requiredClaim));

        /// <summary>
        /// Enables lifetime validation. 
        /// </summary>
        /// <param name="requireExpirationTime">Defines whether the 'exp' claim must be present.</param>
        /// <param name="clockSkew">Defines the time span in seconds to apply.</param>
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
        /// Requires a least one audience contained in the <paramref name="audiences"/>.
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
        /// Requires a specific issuer. This value is used if no issuer is defined by the method <see cref="RequireIssuer(string, IKeyProvider, SignatureAlgorithm?)"/>.
        /// </summary>
        /// <param name="issuer"></param>
        /// <returns></returns>
        public TokenValidationPolicyBuilder DefaultIssuer(string issuer)
        {
            if (string.IsNullOrEmpty(issuer))
            {
                throw new ArgumentNullException(nameof(issuer));
            }

            _issuers.Add(Utf8.GetBytes(issuer));
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
        /// Ignore the 'crit' header if present. <seealso cref="AddCriticalHeaderHandler(string, ICriticalHeaderHandler)"/>
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
        /// Ignores the nested token. If a JWE contains a nested JWS, the nested token will be leaved as uncompress and decrypted binary data.
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
        /// Defines the <see cref="Jwks"/> used to decrypt the tokens.
        /// </summary>
        /// <returns></returns>
        public TokenValidationPolicyBuilder WithDecryptionKeys(Jwks decryptionKeys)
            => WithDecryptionKeys(new StaticKeyProvider(decryptionKeys));

        /// <summary>
        /// Defines the <see cref="Jwk"/> used to decrypt the tokens.
        /// </summary>
        /// <returns></returns>
        public TokenValidationPolicyBuilder WithDecryptionKey(Jwk encryptionKey)
             => WithDecryptionKeys(new Jwks(encryptionKey));

        /// <summary>
        /// Disabled the header cache. This may be useful if the headers are complex or  
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

        /// <summary>
        /// Convert the <see cref="TokenValidationPolicyBuilder"/> into a <see cref="TokenValidationPolicy"/>.
        /// </summary>
        /// <param name="builder"></param>
        public static implicit operator TokenValidationPolicy?(TokenValidationPolicyBuilder builder)
            => builder?.Build();

        private sealed class EmptyKeyProvider : IKeyProvider
        {
            private static readonly Jwk[] Empty = Array.Empty<Jwk>();

            public Jwk[] GetKeys(JwtHeaderDocument header)
                => Empty;

            public string Issuer => string.Empty;
        }
    }
}
