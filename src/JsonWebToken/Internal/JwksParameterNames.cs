// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System;

namespace JsonWebToken.Internal
{
    /// <summary>
    /// Names for Json Web Key Set Values
    /// </summary>
    internal static class JwksParameterNames
    {
        public static ReadOnlySpan<byte> KeysUtf8 => new byte[] { (byte)'k', (byte)'e', (byte)'y', (byte)'s' };
    }
}
