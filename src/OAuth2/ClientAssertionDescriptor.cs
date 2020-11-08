// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System.Text.Json;
using JsonWebToken.Internal;

namespace JsonWebToken
{
    /// <summary>
    /// https://tools.ietf.org/html/rfc7523#section-2.2
    /// </summary>
    public sealed class ClientAssertionDescriptor : JwsDescriptor
    {
        public ClientAssertionDescriptor()
        {
        }

        public ClientAssertionDescriptor(JwtPayload payload) : base(payload)
        {
        }

        public override void Validate()
        {
            if (Key is null)
            {
                throw new JwtDescriptorException("No key is defined.");
            }

            base.Validate();

            RequireClaim(Claims.Iss, JsonValueKind.String);
            RequireClaim(Claims.Sub, JsonValueKind.String);
            ValidateClaim(Claims.Aud, new[] { JsonValueKind.String, JsonValueKind.Array });
            RequireClaim(Claims.Exp, JsonValueKind.Number);
        }
    }
}
