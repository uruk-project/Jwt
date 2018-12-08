// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

namespace JsonWebToken
{
    /// <summary>
    /// List of registered claims from different sources
    /// https://tools.ietf.org/html/draft-ietf-secevent-token-13#section-2.2
    /// </summary>
    public static class SetClaims
    {
        /// <summary>
        /// https://tools.ietf.org/html/draft-ietf-secevent-token-13#section-2.2
        /// </summary>
        public const string Events = "events";

        /// <summary>
        /// https://tools.ietf.org/html/draft-ietf-secevent-token-13#section-2.2
        /// </summary>
        public const string Txn = "txn";

        /// <summary>
        /// https://tools.ietf.org/html/draft-ietf-secevent-token-13#section-2.2
        /// </summary>
        public const string Toe = "toe";
    }
}
