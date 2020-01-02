// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System;

namespace JsonWebToken.Internal
{
    /// <summary>
    /// List of registered claims from different sources
    /// http://tools.ietf.org/html/rfc7519#section-4
    /// http://openid.net/specs/openid-connect-core-1_0.html#IDToken
    /// http://openid.net/specs/openid-connect-core-1_0.html#StandardClaims
    /// http://openid.net/specs/openid-connect-frontchannel-1_0.html#OPLogout
    /// https://tools.ietf.org/html/draft-ietf-secevent-token-13#section-2.2
    /// </summary>
    public static class Claims
    {     
        /// <summary>
        /// http://tools.ietf.org/html/rfc7519#section-4
        /// </summary> 
        public static ReadOnlySpan<byte> AudUtf8 => new byte[] { (byte)'a', (byte)'u', (byte)'d' };
        
        /// <summary>
        /// http://tools.ietf.org/html/rfc7519#section-4
        /// </summary>
        public static ReadOnlySpan<byte> ExpUtf8 => new byte[] { (byte)'e', (byte)'x', (byte)'p' };
        
        /// <summary>
        /// http://tools.ietf.org/html/rfc7519#section-4
        /// </summary>
        public static ReadOnlySpan<byte> IatUtf8 => new byte[] { (byte)'i', (byte)'a', (byte)'t' };
        
        /// <summary>
        /// http://tools.ietf.org/html/rfc7519#section-4
        /// </summary>
        public static ReadOnlySpan<byte> IssUtf8 => new byte[] { (byte)'i', (byte)'s', (byte)'s' };
        
        /// <summary>
        /// http://tools.ietf.org/html/rfc7519#section-4
        /// </summary>
        public static ReadOnlySpan<byte> JtiUtf8 => new byte[] { (byte)'j', (byte)'t', (byte)'i' };
        
        /// <summary>
        /// http://tools.ietf.org/html/rfc7519#section-4
        /// </summary>
        public static ReadOnlySpan<byte> NbfUtf8 => new byte[] { (byte)'n', (byte)'b', (byte)'f' };
        
        /// <summary>
        /// http://tools.ietf.org/html/rfc7519#section-4
        /// </summary>
        public static ReadOnlySpan<byte> SubUtf8 => new byte[] { (byte)'s', (byte)'u', (byte)'b' };
    }
}
