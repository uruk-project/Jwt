// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System.Text.Json;
using JsonWebToken.Internal;

namespace JsonWebToken
{
    /// <summary>
    /// https://tools.ietf.org/html/rfc7591#section-2.3
    /// </summary>
    public sealed class SoftwareStatementDescriptor : JwsDescriptor
    {
        public SoftwareStatementDescriptor(SignatureAlgorithm alg, Jwk signingKey) 
            : base(signingKey, alg)
        {
        }

        public override void Validate()
        {
            base.Validate();
            RequireClaim(Claims.Iss, JsonValueKind.String);
        }
    }
}
