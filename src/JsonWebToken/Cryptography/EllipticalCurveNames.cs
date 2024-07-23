// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

#if SUPPORT_ELLIPTIC_CURVE
using System.Text.Json;

namespace JsonWebToken
{
    /// <summary>Constants for JsonWebKey Elliptical Curve Types. 
    /// https://tools.ietf.org/html/rfc7518#section-6.2.1.1 </summary>
    public static class EllipticalCurveNames
    {
        /// <summary>'P-256'.</summary>
        public static readonly JsonEncodedText P256 = JsonEncodedText.Encode("P-256"u8);
   
        /// <summary>'P-384'.</summary>
        public static readonly JsonEncodedText P384 = JsonEncodedText.Encode("P-384"u8);
        
        /// <summary>'P-521'.</summary>    
        public static readonly JsonEncodedText P521 = JsonEncodedText.Encode("P-521"u8);
        
        /// <summary>'secp256k1'.</summary>    
        public static readonly JsonEncodedText Secp256k1 = JsonEncodedText.Encode("secp256k1"u8);

        /// <summary>Gets all the well-known curve names.</summary>
        public static JsonEncodedText[] All => new[] { P256, P384, P521, Secp256k1 };
    }
}
#endif