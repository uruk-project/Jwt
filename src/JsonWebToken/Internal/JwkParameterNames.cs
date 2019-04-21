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
        public static ReadOnlySpan<byte> AlgUtf8 => new byte[] { (byte)'a', (byte)'l', (byte)'g' };
        public static ReadOnlySpan<byte> KeyOpsUtf8 => new byte[] { (byte)'k', (byte)'e', (byte)'y', (byte)'_', (byte)'o', (byte)'p', (byte)'s' };
        public static ReadOnlySpan<byte> KidUtf8 => new byte[] { (byte)'k', (byte)'i', (byte)'d' };
        public static ReadOnlySpan<byte> KtyUtf8 => new byte[] { (byte)'k', (byte)'t', (byte)'y' };

        public static ReadOnlySpan<byte> UseUtf8 => new byte[] { (byte)'u', (byte)'s', (byte)'e' };
        public static ReadOnlySpan<byte> X5cUtf8 => new byte[] { (byte)'x', (byte)'5', (byte)'c' };
        public static ReadOnlySpan<byte> X5uUtf8 => new byte[] { (byte)'x', (byte)'5', (byte)'u' };
        public static ReadOnlySpan<byte> X5tUtf8 => new byte[] { (byte)'x', (byte)'6', (byte)'t' };
        public static ReadOnlySpan<byte> X5tS256Utf8 => new byte[] { (byte)'x', (byte)'5', (byte)'t', (byte)'#', (byte)'S', (byte)'2', (byte)'5', (byte)'6' };
        public static ReadOnlySpan<byte> OthUtf8 => new byte[] { (byte)'o', (byte)'t', (byte)'h' };

        public static ReadOnlySpan<byte> KUtf8 => new byte[] { (byte)'k' };

        public static ReadOnlySpan<byte> CrvUtf8 => new byte[] { (byte)'c', (byte)'r', (byte)'v' };

        public static ReadOnlySpan<byte> XUtf8 => new byte[] { (byte)'x' };
        public static ReadOnlySpan<byte> YUtf8 => new byte[] { (byte)'y' };
        public static ReadOnlySpan<byte> DUtf8 => new byte[] { (byte)'d' };

        public static ReadOnlySpan<byte> DPUtf8 => new byte[] { (byte)'d', (byte)'p' };
        public static ReadOnlySpan<byte> DQUtf8 => new byte[] { (byte)'d', (byte)'q' };
        public static ReadOnlySpan<byte> EUtf8 => new byte[] { (byte)'e' };

        public static ReadOnlySpan<byte> NUtf8 => new byte[] { (byte)'n' };
        public static ReadOnlySpan<byte> PUtf8 => new byte[] { (byte)'p' };
        public static ReadOnlySpan<byte> QUtf8 => new byte[] { (byte)'q' };
        public static ReadOnlySpan<byte> RUtf8 => new byte[] { (byte)'r' };
        public static ReadOnlySpan<byte> TUtf8 => new byte[] { (byte)'t' };
        public static ReadOnlySpan<byte> QIUtf8 => new byte[] { (byte)'q', (byte)'i' };
    }
}
