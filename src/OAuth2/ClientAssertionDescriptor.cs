// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

using JsonWebToken.Internal;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;

namespace JsonWebToken
{
    /// <summary>
    /// https://tools.ietf.org/html/rfc7523#section-2.2
    /// </summary>
    public class ClientAssertionDescriptor : JwsDescriptor
    {
        private static readonly IReadOnlyDictionary<string, JTokenType[]> ClientAssertionRequiredClaims = new Dictionary<string, JTokenType[]>           
        {
            { Claims.Iss, new [] { JTokenType.String } },
            { Claims.Sub, new [] { JTokenType.String } },
            { Claims.Aud, new [] { JTokenType.String, JTokenType.Array } },
            { Claims.Exp, new [] { JTokenType.Integer } }
        };

        public ClientAssertionDescriptor()
            : base()
        {
        }

        public ClientAssertionDescriptor(JObject payload)
            : base(new Dictionary<string, object>(), payload)
        {
        }

        public ClientAssertionDescriptor(IDictionary<string, object> header, JObject payload)
            : base(header, payload)
        {
        }

        public override void Validate()
        {
            if (Key == null)
            {
                throw new JwtDescriptorException("No key is defined.");
            }

            base.Validate();
        }

        protected override IReadOnlyDictionary<string, JTokenType[]> RequiredClaims => ClientAssertionRequiredClaims;
    }
}
