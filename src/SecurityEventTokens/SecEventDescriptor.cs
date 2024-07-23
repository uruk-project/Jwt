// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

namespace JsonWebToken
{
    /// <summary>Defines a signed Security Event Token. <seealso cref="EncryptedSecEventDescriptor"/> for encrypted Security Event Token.</summary>
    public sealed class SecEventDescriptor : JwsDescriptor
    {
        /// <summary>Initializes a new instance of <see cref="SecEventDescriptor"/> without signature, algorithm "none".</summary>
        /// <param name="typ">Optional. The media type.</param>
        /// <param name="cty">Optional. The content type.</param>
        /// <remarks>This descriptor does not manage signature, it cannot be considered as secure.</remarks>
        public SecEventDescriptor(string? typ = SecEventsMediaTypes.SecEvent, string? cty = null)
            : base(Jwk.None, SignatureAlgorithm.None, typ, cty)
        {
        }
        
        public SecEventDescriptor(SymmetricJwk signingKey, SymmetricSignatureAlgorithm alg, string? typ = SecEventsMediaTypes.SecEvent, string? cty = null)
            : base(signingKey, alg, typ, cty)
        {
        }
        
        public SecEventDescriptor(RsaJwk signingKey, RsaSignatureAlgorithm alg, string? typ = SecEventsMediaTypes.SecEvent, string? cty = null)
            : base(signingKey, alg, typ, cty)
        {
        }
        
        public SecEventDescriptor(ECJwk signingKey, ECSignatureAlgorithm alg, string? typ = SecEventsMediaTypes.SecEvent, string? cty = null)
            : base(signingKey, alg, typ, cty)
        {
        }

        public override void Validate()
        {
            base.Validate();
            CheckRequiredClaimAsString(JwtClaimNames.Iss);
            CheckRequiredClaimAsInteger(JwtClaimNames.Iat);
            CheckRequiredClaimAsString(JwtClaimNames.Jti);
            if (TryGetClaim(SecEventClaimNames.Events, out var events))
            {
                if (events.Type == JwtValueKind.Object)
                {
                    JsonObject evts = (JsonObject)events.Value;
                    foreach (JwtMember evt in evts)
                    {
                        if (evt.Value is SecEvent evcts)
                        {
                            evcts.Validate();
                        }
                    }
                }
                else
                {
                    ThrowHelper.ThrowJwtDescriptorException_ClaimMustBeOfType(SecEventClaimNames.Events, JwtValueKind.Object);
                }
            }
            else
            {
                ThrowHelper.ThrowJwtDescriptorException_ClaimIsRequired(SecEventClaimNames.Events);
            }
        }
    }
}
