// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

using System;
using System.Collections.Generic;
using JsonWebToken.Internal;
using Newtonsoft.Json.Linq;

namespace JsonWebToken
{
    /// <summary>
    /// https://tools.ietf.org/html/rfc7523#section-2.2
    /// </summary>
    public class ClientAssertionDescriptor : JwsDescriptor
    {
        private static readonly IReadOnlyDictionary<string, Type[]> ClientAssertionRequiredClaims = new Dictionary<string, Type[]>
        {
            { Claims.Iss, new [] { typeof(string) } },
            { Claims.Sub, new [] { typeof(string) } },
            { Claims.Aud, new [] { typeof(string), typeof(IList<string>) } },
            { Claims.Exp, new [] { typeof(long) } }
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

        protected override IReadOnlyDictionary<string, Type[]> RequiredClaims => ClientAssertionRequiredClaims;
    }
}
