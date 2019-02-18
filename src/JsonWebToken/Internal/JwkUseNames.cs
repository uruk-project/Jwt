// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

using System;

namespace JsonWebToken.Internal
{
    /// <summary>
    /// Constants for JsonWebKeyUse (sec 4.2)
    /// http://tools.ietf.org/html/rfc7517#section-4
    /// </summary>
    public static class JwkUseNames
    {
        /// <summary>
        /// Gets the 'sig' (signature) value for the 'use' header parameter.
        /// </summary>
        public static ReadOnlySpan<byte> Sig => new byte[] { (byte)'s', (byte)'i', (byte)'g' };

        /// <summary>
        /// Gets the 'enc' (encryption) value for the 'use' header parameter.
        /// </summary>
        public static ReadOnlySpan<byte> Enc => new byte[] { (byte)'e', (byte)'n', (byte)'c' };
    }
}
