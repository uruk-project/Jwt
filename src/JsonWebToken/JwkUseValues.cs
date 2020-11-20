// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System.Text.Json;

namespace JsonWebToken
{
    /// <summary>
    /// Constants for the 'use' parameter (sec 4.2)
    /// http://tools.ietf.org/html/rfc7517#section-4
    /// </summary>
    public static class JwkUseValues
    {
        /// <summary>
        /// Gets the 'sig' (signature) value for the 'use' parameter.
        /// </summary>
        public static readonly JsonEncodedText Sig = JsonEncodedText.Encode("sig");

        /// <summary>
        /// Gets the 'enc' (encryption) value for the 'use' parameter.
        /// </summary>
        public static readonly JsonEncodedText Enc = JsonEncodedText.Encode("enc");
    }
}
