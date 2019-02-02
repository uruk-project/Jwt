// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

using JsonWebToken.Internal;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;

namespace JsonWebToken
{
    /// <summary>
    /// https://tools.ietf.org/html/rfc7523#section-2.2
    /// </summary>
    public class ClientAssertionDescriptor : JwsDescriptor
    {
        private static readonly ReadOnlyDictionary<ReadOnlyMemory<byte>, JwtTokenType[]> ClientAssertionRequiredClaims = new ReadOnlyDictionary<ReadOnlyMemory<byte>, JwtTokenType[]>(
            new Dictionary<ReadOnlyMemory<byte>, JwtTokenType[]>           
        {
            { Claims.IssUtf8, new [] { JwtTokenType.String } },
            { Claims.SubUtf8, new [] { JwtTokenType.String } },
            { Claims.AudUtf8, new [] { JwtTokenType.String, JwtTokenType.Array } },
            { Claims.ExpUtf8, new [] { JwtTokenType.Integer } }
        });

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
            if (Key == null)
            {
                throw new JwtDescriptorException("No key is defined.");
            }

            base.Validate();
        }

        protected override ReadOnlyDictionary<ReadOnlyMemory<byte>, JwtTokenType[]> RequiredClaims => ClientAssertionRequiredClaims;
    }
}
