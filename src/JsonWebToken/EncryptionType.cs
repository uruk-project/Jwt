// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

namespace JsonWebToken
{
    /// <summary>
    /// Defines the algorithm encryption types.
    /// </summary>
    public enum EncryptionType
    {
        None = 0,
        AesHmac,
        AesGcm
    }
}
