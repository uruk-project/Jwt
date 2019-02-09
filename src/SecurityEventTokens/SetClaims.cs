// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

using System.Text;

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
        public static readonly byte[] EventsUtf8 = Encoding.UTF8.GetBytes(Events);

        /// <summary>
        /// https://tools.ietf.org/html/draft-ietf-secevent-token-13#section-2.2
        /// </summary>
        public const string Txn = "txn";
        public static readonly byte[] TxnUtf8 = Encoding.UTF8.GetBytes(Txn);

        /// <summary>
        /// https://tools.ietf.org/html/draft-ietf-secevent-token-13#section-2.2
        /// </summary>
        public const string Toe = "toe";
        public static readonly byte[] ToeUtf8 = Encoding.UTF8.GetBytes(Toe);
    }
}
