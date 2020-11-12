// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System.Text.Json;
using JsonWebToken.Internal;

namespace JsonWebToken
{
    /// <summary>Defines a signed Security Event Token. <seealso cref="EncryptedSecEventDescriptor"/> for encrypted Security Event Token.</summary>
    public class SecEventDescriptor : JwsDescriptor
    {
        public SecEventDescriptor(Jwk signingKey, SignatureAlgorithm alg, string? typ = SecEventsMediaTypes.SecEvent, string? cty = null)
            : base(signingKey, alg, typ, cty)
        {
        }

        public override void Validate()
        {
            base.Validate();
            RequireClaim(Claims.Iss, JsonValueKind.String);
            RequireClaim(Claims.Iat, JsonValueKind.Number);
            RequireClaim(Claims.Jti, JsonValueKind.String);
            RequireClaim(SecEventClaims.Events, JsonValueKind.Object);
        }
    }
}
