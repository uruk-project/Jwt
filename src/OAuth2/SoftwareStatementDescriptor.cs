// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

using JsonWebToken.Internal;
using Newtonsoft.Json.Linq;
using System.Collections.Generic;
using System.Collections.ObjectModel;

namespace JsonWebToken
{
    /// <summary>
    /// https://tools.ietf.org/html/rfc7591#section-2.3
    /// </summary>
    public class SoftwareStatementDescriptor : JwsDescriptor
    {
        private static readonly ReadOnlyDictionary<string, JTokenType[]> SoftwareStatementRequiredClaims = new ReadOnlyDictionary<string, JTokenType[]>(
            new Dictionary<string, JTokenType[]>
            {
                { Claims.Iss, new [] { JTokenType.String} }
            });

        public SoftwareStatementDescriptor(JObject payload)
            : base(new Dictionary<string, object>(), payload)
        {
        }

        /// <summary>
        /// Gets or sets the value of the 'software_id' claim.
        /// </summary>
        public string SoftwareId
        {
            get { return GetStringClaim(Claims.SoftwareId); }
            set { AddClaim(Claims.SoftwareId, value); }
        }

        protected override ReadOnlyDictionary<string, JTokenType[]> RequiredClaims => SoftwareStatementRequiredClaims;
    }
}
