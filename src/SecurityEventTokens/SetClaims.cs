// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System;

namespace JsonWebToken
{
    /// <summary>
    /// List of registered claims from different sources
    /// https://tools.ietf.org/html/draft-ietf-secevent-token-13#section-2.2
    /// </summary>
    public static class SetClaims
    {
        /// <summary>
        /// https://tools.ietf.org/html/rfc8417#section-2.2
        /// </summary>
        public static ReadOnlySpan<byte> EventsUtf8 => new byte[] { (byte)'e', (byte)'v', (byte)'e', (byte)'n', (byte)'t', (byte)'s' };

        /// <summary>
        /// https://tools.ietf.org/html/rfc8417#section-2.2
        /// </summary>
        public static ReadOnlySpan<byte> TxnUtf8 => new byte[] { (byte)'t', (byte)'x', (byte)'n' };

        /// <summary>
        /// https://tools.ietf.org/html/rfc8417#section-2.2
        /// </summary>
        public static ReadOnlySpan<byte> ToeUtf8 => new byte[]{(byte)'t', (byte)'o', (byte)'e'};
    }
}
