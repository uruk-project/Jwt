// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

namespace JsonWebToken.Internal
{
    public class IssuerValidation : RequiredClaimValidation<string>
    {
        public IssuerValidation(string issuer)
            :base(Claims.Iss, issuer)
        {
        }
    }
}
