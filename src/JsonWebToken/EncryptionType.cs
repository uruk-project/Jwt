// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

namespace JsonWebToken
{
    /// <summary>
    /// Defines the algorithm encryption types.
    /// </summary>
    public enum EncryptionType
    {
        /// <summary>
        /// Not supported encryption.
        /// </summary>
        NotSupported = 0,

        /// <summary>
        /// AES-HMAC encryption.
        /// </summary>
        AesHmac,

        /// <summary>
        /// AES-GCM encryption.
        /// </summary>
        AesGcm
    }
}
