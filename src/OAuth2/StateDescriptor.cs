// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System.Text.Json;
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
        
        public override void Validate()
        {
            base.Validate();

            RequireClaim(OAuth2Claims.Rfp , JsonValueKind.String);
        }
    }
}
