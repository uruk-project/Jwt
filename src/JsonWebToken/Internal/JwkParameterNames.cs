// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

using System;
using System.Text;

namespace JsonWebToken.Internal
{
    /// <summary>
    /// Names for Json Web Key Values
    /// </summary>
    internal static class JwkParameterNames
    {
        public const string Alg = "alg";
        public static ReadOnlySpan<byte> AlgUtf8 => new byte[] { (byte)'a', (byte)'l', (byte)'g' };
        public const string KeyOps = "key_ops";
        public static ReadOnlySpan<byte> KeyOpsUtf8 => new byte[] { (byte)'k', (byte)'e', (byte)'y', (byte)'_', (byte)'o', (byte)'p', (byte)'s' };
        public const string Kid = "kid";
        public static ReadOnlySpan<byte> KidUtf8 => new byte[] { (byte)'k', (byte)'i', (byte)'d' };
        public const string Kty = "kty";
        public static ReadOnlySpan<byte> KtyUtf8 => new byte[] { (byte)'k', (byte)'t', (byte)'y' };

        public const string Use = "use";
        public static ReadOnlySpan<byte> UseUtf8 => new byte[] { (byte)'u', (byte)'s', (byte)'e' };
        public const string X5c = "x5c";
        public static ReadOnlySpan<byte> X5cUtf8 => new byte[] { (byte)'x', (byte)'5', (byte)'c' };
        public const string X5u = "x5u";
        public static ReadOnlySpan<byte> X5uUtf8 => new byte[] { (byte)'x', (byte)'5', (byte)'u' };
        public const string X5t = "x5t";
        public static ReadOnlySpan<byte> X5tUtf8 => new byte[] { (byte)'x', (byte)'6', (byte)'t' };
        public const string X5tS256 = "x5t#S256";
        public static ReadOnlySpan<byte> X5tS256Utf8 => new byte[] { (byte)'x', (byte)'5', (byte)'t', (byte)'#', (byte)'S', (byte)'2', (byte)'5', (byte)'6' };
        public const string Oth = "oth";
        public static ReadOnlySpan<byte> OthUtf8 => new byte[] { (byte)'o', (byte)'t', (byte)'h' };

        public const string K = "k";
        public static ReadOnlySpan<byte> KUtf8 => new byte[] { (byte)'k' };

        public const string Crv = "crv";
        public static ReadOnlySpan<byte> CrvUtf8 => new byte[] { 99, 114, 118 };

        public const string X = "x";
        public static ReadOnlySpan<byte> XUtf8 => new byte[] { (byte)'x' };
        public const string Y = "y";
        public static ReadOnlySpan<byte> YUtf8 => new byte[] { (byte)'y' };
        public const string D = "d";
        public static ReadOnlySpan<byte> DUtf8 => new byte[] { (byte)'d' };

        public const string DP = "dp";
        public static ReadOnlySpan<byte> DPUtf8 => new byte[] { (byte)'d', (byte)'p' };
        public const string DQ = "dq";
        public static ReadOnlySpan<byte> DQUtf8 => new byte[] { (byte)'d', (byte)'q' };
        public const string E = "e";
        public static ReadOnlySpan<byte> EUtf8 => new byte[] { (byte)'e' };

        public const string N = "n";
        public static ReadOnlySpan<byte> NUtf8 => new byte[] { (byte)'n' };
        public const string P = "p";
        public static ReadOnlySpan<byte> PUtf8 => new byte[] { (byte)'p' };
        public const string Q = "q";
        public static ReadOnlySpan<byte> QUtf8 => new byte[] { (byte)'q' };
        public const string R = "r";
        public static ReadOnlySpan<byte> RUtf8 => new byte[] { (byte)'r' };
        public const string T = "t";
        public static ReadOnlySpan<byte> TUtf8 => new byte[] { (byte)'t' };
        public const string QI = "qi";
        public static ReadOnlySpan<byte> QIUtf8 => new byte[] { (byte)'q', (byte)'i' };
    }
}
