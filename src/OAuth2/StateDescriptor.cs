// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

using JsonWebToken.Internal;
using Newtonsoft.Json.Linq;
using System.Collections.Generic;
using System.Collections.ObjectModel;

namespace JsonWebToken
{
    public class StateDescriptor : JwsDescriptor
    {
        private static readonly ReadOnlyDictionary<string, JwtTokenType[]> StateRequiredClaims = new ReadOnlyDictionary<string, JwtTokenType[]>(
              new Dictionary<string, JwtTokenType[]>
              {
                { OAuth2Claims.Rfp, new [] { JwtTokenType.String} }
              });

        public StateDescriptor()
        {
        }

        public StateDescriptor(JwtObject header, JwtObject payload)
            : base(header, payload)
        {
        }

        protected override ReadOnlyDictionary<string, JwtTokenType[]> RequiredClaims => StateRequiredClaims;

        /// <summary>
        /// Gets or sets the value of the 'rfp' claim.
        /// </summary>
        public string RequestForgeryProtection
        {
            get { return GetStringClaim(OAuth2Claims.Rfp); }
            set { AddClaim(OAuth2Claims.Rfp, value); }
        }

        /// <summary>
        /// Gets or sets the value of the 'target_link_uri' claim.
        /// </summary>
        public string TargetLinkUri
        {
            get { return GetStringClaim(OAuth2Claims.TargetLinkUri); }
            set { AddClaim(OAuth2Claims.TargetLinkUri, value); }
        }

        /// <summary>
        /// Gets or sets the value of the 'rfp' claim.
        /// </summary>
        public string AuthorizationServer
        {
            get { return GetStringClaim(OAuth2Claims.As); }
            set { AddClaim(OAuth2Claims.As, value); }
        }

        /// <summary>
        /// Gets or sets the value of the 'at_hash' claim.
        /// </summary>
        public string AccessTokenHash
        {
            get => GetStringClaim(OAuth2Claims.AtHash);
            set => AddClaim(OAuth2Claims.AtHash, value);
        }

        /// <summary>     
        /// Gets or sets the value of the 'c_hash' claim.
        /// </summary>
        public string CodeHash
        {
            get => GetStringClaim(OAuth2Claims.CHash);
            set => AddClaim(OAuth2Claims.CHash, value);
        }
    }
}
