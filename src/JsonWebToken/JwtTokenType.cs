// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

namespace JsonWebToken
{
    /// <summary>
    /// Specifies the type of token.
    /// </summary>
    public enum JwtTokenType : byte
    {
        /// <summary>
        ///  A null value. 
        /// </summary>
        Null = 0,

        /// <summary>
        /// A JSON object.
        /// </summary>
        Object = 1,

        /// <summary>
        /// A JSON array.
        /// </summary>
        Array = 2,

        /// <summary>
        /// An integer value.
        /// </summary>
        Integer = 3,

        /// <summary>
        /// A float value.
        /// </summary>
        Float = 4,

        /// <summary>
        /// A string value.
        /// </summary>
        String = 5,

        /// <summary>
        /// A byte array representing a UTF8 string.
        /// </summary>
        Utf8String = 8,

        /// <summary>
        ///  A boolean value.
        /// </summary>
        Boolean = 7,

        /// <summary>
        /// A signature algorithm.
        /// </summary>
        SignatureAlgorithm = 9,

        /// <summary>
        /// A key management algorithm.
        /// </summary>
        KeyManagementAlgorithm = 10,

        /// <summary>
        /// And encryption algorithm.
        /// </summary>
        EncryptionAlgorithm = 11,
        CompressionAlgorithm = 12
    }
}