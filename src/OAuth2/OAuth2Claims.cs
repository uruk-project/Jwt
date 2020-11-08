// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System;

namespace JsonWebToken.Internal
{
    /// <summary>
    /// List of registered claims from different sources
    /// http://tools.ietf.org/html/rfc7519#section-4
    /// https://tools.ietf.org/html/draft-ietf-oauth-token-exchange-14
    /// https://tools.ietf.org/html/draft-bradley-oauth-jwt-encoded-state-09
    /// https://tools.ietf.org/html/draft-richer-vectors-of-trust-11
    /// </summary>
    public static class OAuth2Claims
    {
        /// <summary>
        /// https://tools.ietf.org/html/rfc7591#section-2
        /// </summary>
        public static ReadOnlySpan<byte> SoftwareIdUtf8 => new byte[] { (byte)'s', (byte)'o', (byte)'f', (byte)'t', (byte)'w', (byte)'a', (byte)'r', (byte)'e', (byte)'_', (byte)'i', (byte)'d' };

        /// <summary>
        /// https://tools.ietf.org/html/rfc7591#section-2
        /// </summary>
        public static ReadOnlySpan<byte> VotUtf8 => new byte[] { (byte)'v', (byte)'o', (byte)'t' };

        /// <summary>
        /// https://tools.ietf.org/html/rfc7591#section-2
        /// </summary>
        public static ReadOnlySpan<byte> VtmUtf8 => new byte[] { (byte)'v', (byte)'t', (byte)'m' };

        /// <summary>
        /// https://tools.ietf.org/html/rfc7591#section-2
        /// </summary>
        public static ReadOnlySpan<byte> ActUtf8 => new byte[] { (byte)'a', (byte)'c', (byte)'t' };

        /// <summary>
        /// https://tools.ietf.org/html/rfc7591#section-2
        /// </summary>
        public static ReadOnlySpan<byte> ScopeUtf8 => new byte[] { (byte)'s', (byte)'c', (byte)'o', (byte)'p', (byte)'e' };

        /// <summary>
        /// https://tools.ietf.org/html/rfc7591#section-2
        /// </summary>
        public static ReadOnlySpan<byte> ClientIdUtf8 => new byte[] { (byte)'c', (byte)'l', (byte)'i', (byte)'e', (byte)'n', (byte)'t', (byte)'_', (byte)'i', (byte)'d' };

        /// <summary>
        /// https://tools.ietf.org/html/rfc7591#section-2
        /// </summary>
        public static ReadOnlySpan<byte> MayActUtf8 => new byte[] { (byte)'m', (byte)'a', (byte)'y', (byte)'_', (byte)'a', (byte)'c', (byte)'t' };

        /// <summary>
        /// https://tools.ietf.org/html/rfc7591#section-2
        /// </summary>
        public static ReadOnlySpan<byte> RfpUtf8 => new byte[] { (byte)'r', (byte)'f', (byte)'p' };
        public static readonly string Rfp = "rfp";

        /// <summary>
        /// https://tools.ietf.org/html/rfc7591#section-2
        /// </summary>
        public static ReadOnlySpan<byte> TargetLinkUriUtf8 => new byte[] { (byte)'t', (byte)'a', (byte)'r', (byte)'g', (byte)'e', (byte)'t', (byte)'_', (byte)'l', (byte)'i', (byte)'n', (byte)'k', (byte)'_', (byte)'u', (byte)'r', (byte)'i' };

        /// <summary>
        /// https://tools.ietf.org/html/rfc7591#section-2
        /// </summary>
        public static ReadOnlySpan<byte> AsUtf8 => new byte[] { (byte)'a', (byte)'s' };

        /// <summary>
        /// https://tools.ietf.org/html/rfc7591#section-2
        /// </summary>
        public static ReadOnlySpan<byte> CHashUtf8 => new byte[] { (byte)'c', (byte)'_', (byte)'h', (byte)'a', (byte)'s', (byte)'h' };

        /// <summary>
        /// https://tools.ietf.org/html/rfc7591#section-2
        /// </summary>
        public static ReadOnlySpan<byte> AtHashUtf8 => new byte[] { (byte)'a', (byte)'t', (byte)'_', (byte)'h', (byte)'a', (byte)'s', (byte)'h' };
    }
}
