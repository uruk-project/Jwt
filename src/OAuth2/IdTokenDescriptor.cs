// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

namespace JsonWebToken
{
    /// <summary>Defines a signed ID token. <seealso cref="EncryptedIdTokenDescriptor"/> for encrypted ID token.</summary>
    public sealed class IdTokenDescriptor : JwsDescriptor
    {
        /// <summary>Initializes a new instance of <see cref="IdTokenDescriptor"/> without signature, algorithm "none".</summary>
        /// <param name="typ">Optional. The media type.</param>
        /// <param name="cty">Optional. The content type.</param>
        /// <remarks>This descriptor does not manage signature, it cannot be considered as secure.</remarks>
        public IdTokenDescriptor(string? typ = null, string? cty = null)
            : base(Jwk.None, SignatureAlgorithm.None, typ, cty)
        {
        }
        
        public IdTokenDescriptor(SymmetricSignatureAlgorithm alg, SymmetricJwk signingKey, string? typ = null, string? cty = null)
            : base(signingKey, alg, typ, cty)
        {
        }
        
        public IdTokenDescriptor(RsaSignatureAlgorithm alg, RsaJwk signingKey, string? typ = null, string? cty = null)
            : base(signingKey, alg, typ, cty)
        {
        }
        
        public IdTokenDescriptor(ECSignatureAlgorithm alg, ECJwk signingKey, string? typ = null, string? cty = null)
            : base(signingKey, alg, typ, cty)
        {
        }

        /// <inheritdoc/>
        public override void Validate()
        {
            CheckRequiredClaimAsString(JwtClaimNames.Iss);
            CheckRequiredClaimAsString(JwtClaimNames.Sub);
            CheckRequiredClaimAsStringOrArray(JwtClaimNames.Aud);
            CheckRequiredClaimAsInteger(JwtClaimNames.Exp);
            CheckRequiredClaimAsInteger(JwtClaimNames.Iat);
        }
    }
}
