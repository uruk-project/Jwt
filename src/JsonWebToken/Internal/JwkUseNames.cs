// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

namespace JsonWebToken.Internal
{
    /// <summary>
    /// Constants for JsonWebKeyUse (sec 4.2)
    /// http://tools.ietf.org/html/rfc7517#section-4
    /// </summary>
    internal static class JsonWebKeyUseNames
    {
        public const string Sig = "sig";
        public const string Enc = "enc";
    }
}
