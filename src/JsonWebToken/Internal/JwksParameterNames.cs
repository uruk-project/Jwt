// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

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
