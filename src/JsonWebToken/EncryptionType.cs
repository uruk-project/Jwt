// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System;

namespace JsonWebToken
{
    /// <summary>
    /// Defines the algorithm encryption types.
    /// </summary>
    [Flags]
    public enum EncryptionType
    {
        /// <summary>
        /// Not supported encryption.
        /// </summary>
        NotSupported = 0,

        /// <summary>
        /// AES encryption.
        /// </summary>
        Aes = 0x01,

        /// <summary>
        /// AES-HMAC encryption.
        /// </summary>
        AesHmac = 0x02 | Aes,

        /// <summary>
        /// AES-GCM encryption.
        /// </summary>
        AesGcm = 0x04 | Aes
    }
}
