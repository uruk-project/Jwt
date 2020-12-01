// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System;
using System.Collections.Generic;
using System.Net.Http;

namespace JsonWebToken
{
    public sealed partial class TokenValidationPolicyBuilder
    {
        /// <summary>Ignores the signature validation. This method is obsolete.
        /// Use the methods IgnoreSignatureByDefault() or IgnoreSignature(string issuer) instead.</summary>
        [Obsolete("This method is obsolete. Use the methods " + nameof(IgnoreSignatureByDefault) + " or " + nameof(IgnoreSignature) + " with an issuer parameter instead.", true)]
        public TokenValidationPolicyBuilder IgnoreSignature()
            => throw new NotSupportedException();

        /// <summary>Accepts secure token with the 'none' algorithm. This method is obsolete.
        /// Use the methods AcceptUnsecureTokenByDefault() or AcceptUnsecureToken(string issuer) instead.</summary>
        [Obsolete("This method is obsolete. Use the methods " + nameof(AcceptUnsecureTokenByDefault) + " or " + nameof(AcceptUnsecureToken) + " with an issuer parameter instead.", true)]
        public TokenValidationPolicyBuilder AcceptUnsecureToken()
            => throw new NotSupportedException();

        /// <summary>
        /// Requires a valid signature. This method is obsolete.
        /// Use the methods RequireSignatureByDefault() or RequireSignature(string issuer, IKeyProvider keyProvider, SignatureAlgorithm algorithm) instead.
        /// </summary>
        [Obsolete("This method is obsolete. Use the methods " + nameof(RequireSignatureByDefault) + " or " + nameof(RequireSignature) + " with an issuer parameter instead.", true)]
        public TokenValidationPolicyBuilder RequireSignature(IKeyProvider keyProvider, SignatureAlgorithm? algorithm)
            => throw new NotSupportedException();

        /// <summary>
        /// Requires a valid signature. This method is obsolete.
        /// Use the methods RequireSignatureByDefault() or RequireSignature(string issuer, IKeyProvider keyProvider, SignatureAlgorithm algorithm) instead.
        /// </summary>
        [Obsolete("This method is obsolete. Use the methods " + nameof(RequireSignatureByDefault) + " or " + nameof(RequireSignature) + " with an issuer parameter instead.", true)]
        public TokenValidationPolicyBuilder RequireSignature(IKeyProvider keyProvider)
            => throw new NotSupportedException();

        /// <summary>
        /// Requires a valid signature. This method is obsolete.
        /// Use the methods RequireSignatureByDefault() or RequireSignature(string issuer, IKeyProvider keyProvider, SignatureAlgorithm algorithm) instead.
        /// </summary>
        [Obsolete("This method is obsolete. Use the methods " + nameof(RequireSignatureByDefault) + " or " + nameof(RequireSignature) + " with an issuer parameter instead.", true)]
        public TokenValidationPolicyBuilder RequireSignature(string jwksUrl)
            => throw new NotSupportedException();

        /// <summary>
        /// Requires a valid signature. This method is obsolete.
        /// Use the methods RequireSignatureByDefault() or RequireSignature(string issuer, IKeyProvider keyProvider, SignatureAlgorithm algorithm) instead.
        /// </summary>
        [Obsolete("This method is obsolete. Use the methods " + nameof(RequireSignatureByDefault) + " or " + nameof(RequireSignature) + " with an issuer parameter instead.", true)]
        public TokenValidationPolicyBuilder RequireSignature(string jwksUrl, SignatureAlgorithm algorithm)
            => throw new NotSupportedException();

        /// <summary>
        /// Requires a valid signature. This method is obsolete.
        /// Use the methods RequireSignatureByDefault() or RequireSignature(string issuer, IKeyProvider keyProvider, SignatureAlgorithm algorithm) instead.
        /// </summary>
        [Obsolete("This method is obsolete. Use the methods " + nameof(RequireSignatureByDefault) + " or " + nameof(RequireSignature) + " with an issuer parameter instead.", true)]
        public TokenValidationPolicyBuilder RequireSignature(string jwksUrl, HttpMessageHandler handler)
            => throw new NotSupportedException();

        /// <summary>
        /// Requires a valid signature. This method is obsolete.
        /// Use the methods RequireSignatureByDefault() or RequireSignature(string issuer, IKeyProvider keyProvider, SignatureAlgorithm algorithm) instead.
        /// </summary>
        [Obsolete("This method is obsolete. Use the methods " + nameof(RequireSignatureByDefault) + " or " + nameof(RequireSignature) + " with an issuer parameter instead.", true)]
        public TokenValidationPolicyBuilder RequireSignature(string jwksUrl, SignatureAlgorithm? algorithm, HttpMessageHandler? handler)
            => throw new NotSupportedException();

        /// <summary>
        /// Requires a valid signature. This method is obsolete.
        /// Use the methods RequireSignatureByDefault() or RequireSignature(string issuer, IKeyProvider keyProvider, SignatureAlgorithm algorithm) instead.
        /// </summary>
        [Obsolete("This method is obsolete. Use the methods " + nameof(RequireSignatureByDefault) + " or " + nameof(RequireSignature) + " with an issuer parameter instead.", true)]
        public TokenValidationPolicyBuilder RequireSignature(Jwk key)
            => throw new NotSupportedException();

        /// <summary>
        /// Requires a valid signature. This method is obsolete.
        /// Use the methods RequireSignatureByDefault() or RequireSignature(string issuer, IKeyProvider keyProvider, SignatureAlgorithm algorithm) instead.
        /// </summary>
        [Obsolete("This method is obsolete. Use the methods " + nameof(RequireSignatureByDefault) + " or " + nameof(RequireSignature) + " with an issuer parameter instead.", true)]
        public TokenValidationPolicyBuilder RequireSignature(Jwk key, SignatureAlgorithm? algorithm)
            => throw new NotSupportedException();

        /// <summary>
        /// Requires a valid signature. This method is obsolete.
        /// Use the methods RequireSignatureByDefault() or RequireSignature(string issuer, IKeyProvider keyProvider, SignatureAlgorithm algorithm) instead.
        /// </summary>
        [Obsolete("This method is obsolete. Use the methods " + nameof(RequireSignatureByDefault) + " or " + nameof(RequireSignature) + " with an issuer parameter instead.", true)]
        public TokenValidationPolicyBuilder RequireSignature(Jwk key, string? algorithm)
            => throw new NotSupportedException();

        /// <summary>
        /// Requires a valid signature. This method is obsolete.
        /// Use the methods RequireSignatureByDefault() or RequireSignature(string issuer, IKeyProvider keyProvider, SignatureAlgorithm algorithm) instead.
        /// </summary>
        [Obsolete("This method is obsolete. Use the methods " + nameof(RequireSignatureByDefault) + " or " + nameof(RequireSignature) + " with an issuer parameter instead.", true)]
        public TokenValidationPolicyBuilder RequireSignature(IList<Jwk> keys)
            => throw new NotSupportedException();

        /// <summary>
        /// Requires a valid signature. This method is obsolete.
        /// Use the methods RequireSignatureByDefault() or RequireSignature(string issuer, IKeyProvider keyProvider, SignatureAlgorithm algorithm) instead.
        /// </summary>
        [Obsolete("This method is obsolete. Use the methods " + nameof(RequireSignatureByDefault) + " or " + nameof(RequireSignature) + " with an issuer parameter instead.", true)]
        public TokenValidationPolicyBuilder RequireSignature(IList<Jwk> keys, SignatureAlgorithm? algorithm)
            => throw new NotSupportedException();

        /// <summary>
        /// Requires a valid signature. This method is obsolete.
        /// Use the methods RequireSignatureByDefault() or RequireSignature(string issuer, IKeyProvider keyProvider, SignatureAlgorithm algorithm) instead.
        /// </summary>
        [Obsolete("This method is obsolete. Use the methods " + nameof(RequireSignatureByDefault) + " or " + nameof(RequireSignature) + " with an issuer parameter instead.", true)]
        public TokenValidationPolicyBuilder RequireSignature(Jwks keySet)
            => throw new NotSupportedException();

        /// <summary>
        /// Requires a valid signature. This method is obsolete.
        /// Use the methods RequireSignatureByDefault() or RequireSignature(string issuer, IKeyProvider keyProvider, SignatureAlgorithm algorithm) instead.
        /// </summary>
        [Obsolete("This method is obsolete. Use the methods " + nameof(RequireSignatureByDefault) + " or " + nameof(RequireSignature) + " with an issuer parameter instead.", true)]
        public TokenValidationPolicyBuilder RequireSignature(Jwks keySet, SignatureAlgorithm? algorithm)
            => throw new NotSupportedException();

        /// <summary>
        /// Requires a valid signature. This method is obsolete.
        /// Use the methods RequireSignatureByDefault() or RequireSignature(string issuer, IKeyProvider keyProvider, SignatureAlgorithm algorithm) instead.
        /// </summary>
        [Obsolete("This method is obsolete. Use the methods " + nameof(RequireSignatureByDefault) + " or " + nameof(RequireSignature) + " with an issuer parameter instead.", true)]
        public TokenValidationPolicyBuilder RequireSignature(IEnumerable<IKeyProvider> keyProviders)
            => throw new NotSupportedException();

        /// <summary>
        /// Requires a valid signature. This method is obsolete.
        /// Use the methods RequireSignatureByDefault() or RequireSignature(string issuer, IKeyProvider keyProvider, SignatureAlgorithm algorithm) instead.
        /// </summary>
        [Obsolete("This method is obsolete. Use the methods " + nameof(RequireSignatureByDefault) + " or " + nameof(RequireSignature) + " with an issuer parameter instead.", true)]
        public TokenValidationPolicyBuilder RequireSignature(IEnumerable<IKeyProvider> keyProviders, SignatureAlgorithm? algorithm)
            => throw new NotSupportedException();
    }
}
