// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

namespace JsonWebToken
{
    /// <summary>
    /// Defines the algorithm encryption types.
    /// </summary>
    public enum EncryptionType
    {

        /// <summary>
        /// Undefined encryption.
        /// </summary>
        Undefined = 0,

        /// <summary>
        /// AES-HMAC encryption.
        /// </summary>
        AesHmac,

#if NETCOREAPP3_0
        /// <summary>
        /// AES-GCM encryption.
        /// </summary>
        AesGcm
#endif
    }
}
