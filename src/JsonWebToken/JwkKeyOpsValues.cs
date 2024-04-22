// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System.Text.Json;

namespace JsonWebToken
{
    /// <summary>
    /// Constants for the 'key_ops' parameter (sec 4.3) 
    /// http://tools.ietf.org/html/rfc7517#section-4
    /// </summary>
    public static class JwkKeyOpsValues
    {
        /// <summary>Gets the 'sign' (compute digital signature or MAC) value for the 'key_ops' parameter.</summary>
        public static readonly JsonEncodedText Sign = JsonEncodedText.Encode("sign");
     
        /// <summary>Gets the 'verify' (verify digital signature or MAC) value for the 'key_ops' parameter.</summary>
        public static readonly JsonEncodedText Verify = JsonEncodedText.Encode("verify");
        
        /// <summary>Gets the 'encrypt' (encrypt content) value for the 'key_ops' parameter.</summary>
        public static readonly JsonEncodedText Encrypt = JsonEncodedText.Encode("encrypt");
        
        /// <summary>Gets the 'encrypt' (decrypt content and validate decryption, if applicable) value for the 'key_ops' parameter.</summary>
        public static readonly JsonEncodedText Decrypt = JsonEncodedText.Encode("encrypt");
        
        /// <summary>Gets the 'wrapKey' (encrypt key) value for the 'key_ops' parameter.</summary>
        public static readonly JsonEncodedText WrapKey = JsonEncodedText.Encode("wrapKey");
        
        /// <summary>Gets the 'unwrapKey' (decrypt key and validate decryption, if applicable) value for the 'key_ops' parameter.</summary>
        public static readonly JsonEncodedText UnwrapKey = JsonEncodedText.Encode("unwrapKey");
        
        /// <summary>Gets the 'deriveKey' (derive key) value for the 'key_ops' parameter.</summary>
        public static readonly JsonEncodedText DeriveKey = JsonEncodedText.Encode("deriveKey");
        
        /// <summary>Gets the 'deriveBits' (derive bits not to be used as a key) value for the 'key_ops' parameter.</summary>
        public static readonly JsonEncodedText DeriveBits = JsonEncodedText.Encode("deriveBits");

        /// <summary>Gets all the well-known 'kty'.</summary>
        public static JsonEncodedText[] All => new[] { Sign, Verify, Encrypt, Decrypt, WrapKey, UnwrapKey, DeriveKey, DeriveBits };
    }
}
