// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

using System;
using System.Text;

namespace JsonWebToken.Internal
{
    /// <summary>
    /// Content types values.
    /// </summary>
    public static class ContentTypeValues
    {
        /// <summary>
        /// JWT content type for 'cty' header parameter.
        /// </summary>
        public static readonly string Jwt = "JWT";

        /// <summary>
        /// JWT content type for 'cty' header parameter.
        /// </summary>
        public static ReadOnlySpan<byte> JwtUtf8 => new byte[] { (byte)'J', (byte)'W', (byte)'T' };
    }
}
