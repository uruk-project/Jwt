// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using JsonWebToken.Internal;

namespace JsonWebToken
{
    /// <summary>
    /// https://tools.ietf.org/html/draft-bradley-oauth-jwt-encoded-state-09
    /// </summary>
    public class StateDescriptor : JwsDescriptor
    {
        public StateDescriptor()
        {
        }

        public StateDescriptor(JwtObject header, JwtObject payload)
            : base(header, payload)
        {
        }

        /// <summary>
        /// Gets or sets the value of the 'rfp' claim.
        /// </summary>
        public string? RequestForgeryProtection
        {
            get { return GetStringClaim(OAuth2Claims.RfpUtf8); }
            set { AddClaim(OAuth2Claims.RfpUtf8, value); }
        }

        /// <summary>
        /// Gets or sets the value of the 'target_link_uri' claim.
        /// </summary>
        public string? TargetLinkUri
        {
            get { return GetStringClaim(OAuth2Claims.TargetLinkUriUtf8); }
            set { AddClaim(OAuth2Claims.TargetLinkUriUtf8, value); }
        }

        /// <summary>
        /// Gets or sets the value of the 'rfp' claim.
        /// </summary>
        public string? AuthorizationServer
        {
            get { return GetStringClaim(OAuth2Claims.AsUtf8); }
            set { AddClaim(OAuth2Claims.AsUtf8, value); }
        }

        /// <summary>
        /// Gets or sets the value of the 'at_hash' claim.
        /// </summary>
        public string? AccessTokenHash
        {
            get => GetStringClaim(OAuth2Claims.AtHashUtf8);
            set => AddClaim(OAuth2Claims.AtHashUtf8, value);
        }

        /// <summary>     
        /// Gets or sets the value of the 'c_hash' claim.
        /// </summary>
        public string? CodeHash
        {
            get => GetStringClaim(OAuth2Claims.CHashUtf8);
            set => AddClaim(OAuth2Claims.CHashUtf8, value);
        }

        public override void Validate()
        {
            base.Validate();

            RequireClaim(OAuth2Claims.RfpUtf8, JwtTokenType.String);
        }
    }
}
