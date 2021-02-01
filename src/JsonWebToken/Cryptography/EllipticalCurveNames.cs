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
        public static readonly JsonEncodedText P256 = JsonEncodedText.Encode(new byte[] { (byte)'P', (byte)'-', (byte)'2', (byte)'5', (byte)'6' });
   
        /// <summary>'P-384'.</summary>
        public static readonly JsonEncodedText P384 = JsonEncodedText.Encode(new byte[] { (byte)'P', (byte)'-', (byte)'3', (byte)'8', (byte)'4' });
        
        /// <summary>'P-521'.</summary>    
        public static readonly JsonEncodedText P521 = JsonEncodedText.Encode(new byte[] { (byte)'P', (byte)'-', (byte)'5', (byte)'2', (byte)'1' });
        
        /// <summary>'secp256k1'.</summary>    
        public static readonly JsonEncodedText Secp256k1 = JsonEncodedText.Encode(new byte[] { (byte)'s', (byte)'e', (byte)'c', (byte)'p', (byte)'2', (byte)'5', (byte)'6', (byte)'k', (byte)'1' });

        /// <summary>Gets all the well-known curve names.</summary>
        public static JsonEncodedText[] All => new[] { P256, P384, P521, Secp256k1 };
    }
}
#endif