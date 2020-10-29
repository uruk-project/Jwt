// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

namespace JsonWebToken
{
    /// <summary>
    /// Represents a JWT header.
    /// </summary>
    public interface IJwtHeader
    {
#if SUPPORT_ELLIPTIC_CURVE
        /// <summary>
        /// Gets the ephemeral key used for ECDH key agreement.
        /// </summary>
        ECJwk? Epk { get; }

        /// <summary>
        /// Gets the Agreement PartyUInfo used for ECDH key agreement.
        /// </summary>
        string? Apu { get; }
     
        /// <summary>
        /// Gets the Agreement PartyVInfo used for ECDH key agreement.
        /// </summary>
        string? Apv { get; }
#endif
        /// <summary>
        /// Gets the Initialization Vector used for AES GCM encryption.
        /// </summary>
        string? IV { get; }

        /// <summary>
        /// Gets the Authentication Tag used for AES GCM encryption.
        /// </summary>
        string? Tag { get; }

        /// <summary>
        /// Gets the key identifier for the key used to sign the token.
        /// </summary>
        string? Kid { get; }
    }
}
