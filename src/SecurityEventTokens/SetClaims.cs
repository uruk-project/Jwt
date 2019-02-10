// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

using System;
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
        public static ReadOnlyMemory<byte> EventsUtf8 => new byte[] { (byte)'e', (byte)'v', (byte)'e', (byte)'n', (byte)'t', (byte)'s' };

        /// <summary>
        /// https://tools.ietf.org/html/draft-ietf-secevent-token-13#section-2.2
        /// </summary>
        public const string Txn = "txn";
        public static ReadOnlyMemory<byte> TxnUtf8 => new byte[] { (byte)'t', (byte)'x', (byte)'n' };

        /// <summary>
        /// https://tools.ietf.org/html/draft-ietf-secevent-token-13#section-2.2
        /// </summary>
        public const string Toe = "toe";
        public static ReadOnlyMemory<byte> ToeUtf8 => new byte[]{(byte)'t', (byte)'o', (byte)'e'};
    }
}
