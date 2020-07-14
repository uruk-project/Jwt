// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using JsonWebToken.Internal;

namespace JsonWebToken
{
    /// <summary>
    /// https://tools.ietf.org/html/rfc7523#section-2.2
    /// </summary>
    public sealed class ClientAssertionDescriptor : JwsDescriptor
    {
        public ClientAssertionDescriptor()
            : base()
        {
        }

        public ClientAssertionDescriptor(JwtObject payload)
            : base(new JwtObject(), payload)
        {
        }

        public ClientAssertionDescriptor(JwtObject header, JwtObject payload)
            : base(header, payload)
        {
        }

        public override void Validate()
        {
            if (Key is null)
            {
                throw new JwtDescriptorException("No key is defined.");
            }

            base.Validate();

            RequireClaim(Claims.IssUtf8, JwtTokenType.String);
            RequireClaim(Claims.SubUtf8, JwtTokenType.String);
            ValidateClaim(Claims.AudUtf8, new[] { JwtTokenType.String, JwtTokenType.Array });
            RequireClaim(Claims.ExpUtf8, JwtTokenType.Integer);
        }
    }
}
