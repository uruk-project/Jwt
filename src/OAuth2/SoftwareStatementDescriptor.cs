// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using JsonWebToken.Internal;

namespace JsonWebToken
{
    /// <summary>
    /// https://tools.ietf.org/html/rfc7591#section-2.3
    /// </summary>
    public sealed class SoftwareStatementDescriptor : JwsDescriptor
    {
        public SoftwareStatementDescriptor(JwtObject payload)
            : base(new JwtObject(), payload)
        {
        }

        /// <summary>
        /// Gets or sets the value of the 'software_id' claim.
        /// </summary>
        public string? SoftwareId
        {
            get { return GetStringClaim(OAuth2Claims.SoftwareIdUtf8); }
            set { AddClaim(OAuth2Claims.SoftwareIdUtf8, value); }
        }

        public override void Validate()
        {
            base.Validate();
            RequireClaim(Claims.IssUtf8, JwtTokenType.String);
        }
    }
}
