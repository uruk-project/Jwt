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
        private static readonly ReadOnlyDictionary<string, JTokenType[]> StateRequiredClaims = new ReadOnlyDictionary<string, JTokenType[]>(
              new Dictionary<string, JTokenType[]>
              {
                { Claims.Rfp, new [] { JTokenType.String} }
              });

        public StateDescriptor()
        {
        }

        public StateDescriptor(IDictionary<string, object> header, JObject payload)
            : base(header, payload)
        {
        }

        protected override ReadOnlyDictionary<string, JTokenType[]> RequiredClaims => StateRequiredClaims;

        /// <summary>
        /// Gets or sets the value of the 'rfp' claim.
        /// </summary>
        public string RequestForgeryProtection
        {
            get { return GetStringClaim(Claims.Rfp); }
            set { AddClaim(Claims.Rfp, value); }
        }

        /// <summary>
        /// Gets or sets the value of the 'target_link_uri' claim.
        /// </summary>
        public string TargetLinkUri
        {
            get { return GetStringClaim(Claims.TargetLinkUri); }
            set { AddClaim(Claims.TargetLinkUri, value); }
        }

        /// <summary>
        /// Gets or sets the value of the 'rfp' claim.
        /// </summary>
        public string AuthorizationServer
        {
            get { return GetStringClaim(Claims.As); }
            set { AddClaim(Claims.As, value); }
        }

        /// <summary>
        /// Gets or sets the value of the 'at_hash' claim.
        /// </summary>
        public string AccessTokenHash
        {
            get => GetStringClaim(Claims.AtHash);
            set => AddClaim(Claims.AtHash, value);
        }

        /// <summary>     
        /// Gets or sets the value of the 'c_hash' claim.
        /// </summary>
        public string CodeHash
        {
            get => GetStringClaim(Claims.CHash);
            set => AddClaim(Claims.CHash, value);
        }
    }
}
