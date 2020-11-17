// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System;
using System.Text.Json;

namespace JsonWebToken
{
    /// <summary>
    /// List of registered claims from different sources
    /// https://tools.ietf.org/html/draft-ietf-secevent-token-13#section-2.2
    /// </summary>
    public static class SecEventClaims

    {
        /// <summary>
        /// https://tools.ietf.org/html/rfc8417#section-2.2
        /// </summary>
        public static readonly JsonEncodedText Events = JsonEncodedText.Encode("events");

        /// <summary>
        /// https://tools.ietf.org/html/rfc8417#section-2.2
        /// </summary>
        public static readonly string Txn = "txn";

        /// <summary>
        /// https://tools.ietf.org/html/rfc8417#section-2.2
        /// </summary>
        public static readonly string Toe = "toe";

    }
}
