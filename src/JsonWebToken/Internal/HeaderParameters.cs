// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

using System;
using System.Text;

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
        public const string Alg = "alg";

        /// <summary>
        /// see:https://tools.ietf.org/html/rfc7515#section-4.1.1
        /// </summary>
        public static ReadOnlyMemory<byte> AlgUtf8 => new byte[] { (byte)'a', (byte)'l', (byte)'g' };

        /// <summary>
        /// see:https://tools.ietf.org/html/rfc7515#section-4.1.10
        /// also:https://tools.ietf.org/html/rfc7519#section-5.2
        /// </summary>
        public const string Cty = "cty";
        
        /// <summary>
        /// see:https://tools.ietf.org/html/rfc7515#section-4.1.10
        /// also:https://tools.ietf.org/html/rfc7519#section-5.2
        /// </summary>
        public static ReadOnlyMemory<byte> CtyUtf8 => new byte[] { (byte)'c', (byte)'t', (byte)'y' };

        /// <summary>
        /// see:https://tools.ietf.org/html/rfc7516#section-4.1.2
        /// </summary>
        public const string Enc = "enc";

        /// <summary>
        /// see:https://tools.ietf.org/html/rfc7516#section-4.1.2
        /// </summary>
        public static ReadOnlyMemory<byte> EncUtf8 => new byte[] { (byte)'e', (byte)'n', (byte)'c' };

        /// <summary>
        /// see:https://tools.ietf.org/html/rfc7515#section-4.1.2
        /// </summary>
        public const string Jku = "jku";

        /// <summary>
        /// see:https://tools.ietf.org/html/rfc7516#section-4.1.2
        /// </summary>
        public static ReadOnlyMemory<byte> JkuUtf8 => new byte[] { (byte)'j', (byte)'k', (byte)'u' };

        /// <summary>
        /// see:https://tools.ietf.org/html/rfc7515#section-4.1.3
        /// </summary>
        public const string Jwk = "jwk";

        /// <summary>
        /// see:https://tools.ietf.org/html/rfc7515#section-4.1.3
        /// </summary>
        public static ReadOnlyMemory<byte> JwkUtf8 => new byte[] { (byte)'j', (byte)'w', (byte)'k' };

        /// <summary>
        /// see:https://tools.ietf.org/html/rfc7515#section-4.1.4
        /// </summary>
        public const string Kid = "kid";

        /// <summary>
        /// see:https://tools.ietf.org/html/rfc7515#section-4.1.4
        /// </summary>
        public static ReadOnlyMemory<byte> KidUtf8 => new byte[] { (byte)'k', (byte)'i', (byte)'d' };

        /// <summary>
        /// see:https://tools.ietf.org/html/rfc7515#section-4.1.9
        /// also:https://tools.ietf.org/html/rfc7519#section-5.1
        /// </summary>
        public const string Typ = "typ";

        /// <summary>
        /// see:https://tools.ietf.org/html/rfc7515#section-4.1.9
        /// also:https://tools.ietf.org/html/rfc7519#section-5.1
        /// </summary>
        public static ReadOnlyMemory<byte> TypUtf8 => new byte[] { (byte)'t', (byte)'y', (byte)'p' };

        /// <summary>
        /// see:https://tools.ietf.org/html/rfc7515#section-4.1.6
        /// </summary>
        public const string X5c = "x5c";

        /// <summary>
        /// see:https://tools.ietf.org/html/rfc7515#section-4.1.6
        /// </summary>
        public static ReadOnlyMemory<byte> X5cUtf8 => new byte[] { (byte)'x', (byte)'5', (byte)'c' };

        /// <summary>
        /// see:https://tools.ietf.org/html/rfc7515#page-12
        /// </summary>
        public const string X5t = "x5t";

        /// <summary>
        /// see:https://tools.ietf.org/html/rfc7515#page-12
        /// </summary>
        public static ReadOnlyMemory<byte> X5tUtf8 => new byte[] { (byte)'x', (byte)'5', (byte)'t' };

        /// <summary>
        /// see:https://tools.ietf.org/html/rfc7515#section-4.1.5
        /// </summary>
        public const string X5u = "x5u";

        /// <summary>
        /// see:https://tools.ietf.org/html/rfc7515#section-4.1.5
        /// </summary>
        public static ReadOnlyMemory<byte> X5uUtf8 => new byte[] { (byte)'x', (byte)'5', (byte)'U' };

        /// <summary>
        /// see:https://tools.ietf.org/html/rfc7515#section-4.1.5
        /// </summary>
        public const string Crit = "crit";
        
        /// <summary>
        /// see:https://tools.ietf.org/html/rfc7515#section-4.1.5
        /// </summary>
        public static ReadOnlyMemory<byte> CritUtf8 => new byte[] { (byte)'c', (byte)'r', (byte)'i', (byte)'t' };

        /// <summary>
        /// see:https://tools.ietf.org/html/rfc7516#section-4.1.3
        /// </summary>
        public const string Zip = "zip";

        /// <summary>
        /// see:https://tools.ietf.org/html/rfc7516#section-4.1.3
        /// </summary>
        public static ReadOnlyMemory<byte> ZipUtf8 => new byte[] { (byte)'z', (byte)'i', (byte)'p' };
        
        /// <summary>
        /// see:https://tools.ietf.org/html/rfc7518#section-4.6.1
        /// </summary>
        public const string Epk = "epk";

        /// <summary>
        /// see:https://tools.ietf.org/html/rfc7518#section-4.6.1
        /// </summary>
        public static ReadOnlyMemory<byte> EpkUtf8 => new byte[] { (byte)'e', (byte)'p', (byte)'k' };

        /// <summary>
        /// see:https://tools.ietf.org/html/rfc7518#section-4.6.1
        /// </summary>
        public const string Apu = "apu";

        /// <summary>
        /// see:https://tools.ietf.org/html/rfc7518#section-4.6.1
        /// </summary>
        public static ReadOnlyMemory<byte> ApuUtf8 => new byte[] { (byte)'a', (byte)'p', (byte)'u' };

        /// <summary>
        /// see:https://tools.ietf.org/html/rfc7518#section-4.6.1
        /// </summary>
        public const string Apv = "apv";

        /// <summary>
        /// see:https://tools.ietf.org/html/rfc7518#section-4.6.1
        /// </summary>
        public static ReadOnlyMemory<byte> ApvUtf8 => new byte[] { (byte)'a', (byte)'p', (byte)'v' };

        /// <summary>
        /// see:https://tools.ietf.org/html/rfc7518#section-4.7
        /// </summary>
        public const string IV = "iv";

        /// <summary>
        /// see:https://tools.ietf.org/html/rfc7518#section-4.7
        /// </summary>
        public static ReadOnlyMemory<byte> IVUtf8 => new byte[] { (byte)'i', (byte)'v' };

        /// <summary>
        /// see:https://tools.ietf.org/html/rfc7518#section-4.7
        /// </summary>
        public const string Tag = "tag";

        /// <summary>
        /// see:https://tools.ietf.org/html/rfc7518#section-4.7
        /// </summary>
        public static ReadOnlyMemory<byte> TagUtf8 => new byte[] { (byte)'t', (byte)'a', (byte)'g' };

        /// <summary>
        /// see:https://tools.ietf.org/html/rfc7518#section-4.8
        /// </summary>
        public const string P2s = "p2s";

        /// <summary>
        /// see:https://tools.ietf.org/html/rfc7518#section-4.8
        /// </summary>
        public const string P2c = "p2c";
    }
}
