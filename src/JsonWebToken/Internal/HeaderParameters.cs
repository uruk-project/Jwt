// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System;

namespace JsonWebToken.Internal
{
    /// <summary>
    /// List of header parameter names see: http://tools.ietf.org/html/rfc7519#section-5.
    /// </summary>
    public static class HeaderParameters
    {
        /// <summary>
        /// see:https://tools.ietf.org/html/rfc7515#section-4.1.1
        /// </summary>
        public static ReadOnlySpan<byte> AlgUtf8 => new byte[] { (byte)'a', (byte)'l', (byte)'g' };
        
        /// <summary>
        /// see:https://tools.ietf.org/html/rfc7515#section-4.1.10
        /// also:https://tools.ietf.org/html/rfc7519#section-5.2
        /// </summary>
        public static ReadOnlySpan<byte> CtyUtf8 => new byte[] { (byte)'c', (byte)'t', (byte)'y' };
        
        /// <summary>
        /// see:https://tools.ietf.org/html/rfc7516#section-4.1.2
        /// </summary>
        public static ReadOnlySpan<byte> EncUtf8 => new byte[] { (byte)'e', (byte)'n', (byte)'c' };
        
        /// <summary>
        /// see:https://tools.ietf.org/html/rfc7516#section-4.1.2
        /// </summary>
        public static ReadOnlySpan<byte> JkuUtf8 => new byte[] { (byte)'j', (byte)'k', (byte)'u' };
        
        /// <summary>
        /// see:https://tools.ietf.org/html/rfc7515#section-4.1.3
        /// </summary>
        public static ReadOnlySpan<byte> JwkUtf8 => new byte[] { (byte)'j', (byte)'w', (byte)'k' };
        
        /// <summary>
        /// see:https://tools.ietf.org/html/rfc7515#section-4.1.4
        /// </summary>
        public static ReadOnlySpan<byte> KidUtf8 => new byte[] { (byte)'k', (byte)'i', (byte)'d' };
        
        /// <summary>
        /// see:https://tools.ietf.org/html/rfc7515#section-4.1.9
        /// also:https://tools.ietf.org/html/rfc7519#section-5.1
        /// </summary>
        public static ReadOnlySpan<byte> TypUtf8 => new byte[] { (byte)'t', (byte)'y', (byte)'p' };
        
        /// <summary>
        /// see:https://tools.ietf.org/html/rfc7515#section-4.1.6
        /// </summary>
        public static ReadOnlySpan<byte> X5cUtf8 => new byte[] { (byte)'x', (byte)'5', (byte)'c' };
        
        /// <summary>
        /// see:https://tools.ietf.org/html/rfc7515#page-12
        /// </summary>
        public static ReadOnlySpan<byte> X5tUtf8 => new byte[] { (byte)'x', (byte)'5', (byte)'t' };
        
        /// <summary>
        /// see:https://tools.ietf.org/html/rfc7515#section-4.1.5
        /// </summary>
        public static ReadOnlySpan<byte> X5uUtf8 => new byte[] { (byte)'x', (byte)'5', (byte)'U' };
        
        /// <summary>
        /// see:https://tools.ietf.org/html/rfc7515#section-4.1.5
        /// </summary>
        public static ReadOnlySpan<byte> CritUtf8 => new byte[] { (byte)'c', (byte)'r', (byte)'i', (byte)'t' };

        /// <summary>
        /// see:https://tools.ietf.org/html/rfc7516#section-4.1.3
        /// </summary>
        public static ReadOnlySpan<byte> ZipUtf8 => new byte[] { (byte)'z', (byte)'i', (byte)'p' };

        /// <summary>
        /// see:https://tools.ietf.org/html/rfc7518#section-4.6.1
        /// </summary>
        public static ReadOnlySpan<byte> EpkUtf8 => new byte[] { (byte)'e', (byte)'p', (byte)'k' };
        
        /// <summary>
        /// see:https://tools.ietf.org/html/rfc7518#section-4.6.1
        /// </summary>
        public static ReadOnlySpan<byte> ApuUtf8 => new byte[] { (byte)'a', (byte)'p', (byte)'u' };
        
        /// <summary>
        /// see:https://tools.ietf.org/html/rfc7518#section-4.6.1
        /// </summary>
        public static ReadOnlySpan<byte> ApvUtf8 => new byte[] { (byte)'a', (byte)'p', (byte)'v' };
        
        /// <summary>
        /// see:https://tools.ietf.org/html/rfc7518#section-4.7
        /// </summary>
        public static ReadOnlySpan<byte> IVUtf8 => new byte[] { (byte)'i', (byte)'v' };
        
        /// <summary>
        /// see:https://tools.ietf.org/html/rfc7518#section-4.7
        /// </summary>
        public static ReadOnlySpan<byte> TagUtf8 => new byte[] { (byte)'t', (byte)'a', (byte)'g' };
    }
}
