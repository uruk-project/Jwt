// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

using JsonWebToken.Internal;
using Newtonsoft.Json.Linq;
using System.Collections.Generic;
using System.Collections.ObjectModel;

namespace JsonWebToken
{
    /// <summary>
    /// https://tools.ietf.org/html/rfc7523#section-2.2
    /// </summary>
    public class ClientAssertionDescriptor : JwsDescriptor
    {
        private static readonly ReadOnlyDictionary<string, JwtTokenType[]> ClientAssertionRequiredClaims = new ReadOnlyDictionary<string, JwtTokenType[]>(
            new Dictionary<string, JwtTokenType[]>           
        {
            { Claims.Iss, new [] { JwtTokenType.String } },
            { Claims.Sub, new [] { JwtTokenType.String } },
            { Claims.Aud, new [] { JwtTokenType.String, JwtTokenType.Array } },
            { Claims.Exp, new [] { JwtTokenType.Integer } }
        });

        public ClientAssertionDescriptor()
            : base()
        {
        }

        public ClientAssertionDescriptor(PayloadDescriptor payload)
            : base(new HeaderDescriptor(), payload)
        {
        }

        public ClientAssertionDescriptor(HeaderDescriptor header, PayloadDescriptor payload)
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

        protected override ReadOnlyDictionary<string, JwtTokenType[]> RequiredClaims => ClientAssertionRequiredClaims;
    }
}
