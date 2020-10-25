// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

namespace JsonWebToken
{
    /// <summary>
    /// Defines the valitation status of a JWT.
    /// </summary>
    public enum TokenValidationStatus
    {
        /// <summary>
        /// The token is valid.
        /// </summary>
        Success = 0x00000000,

        /// <summary>
        /// A key error-related occurred.
        /// </summary>
        KeyError = 0x40000000,

        /// <summary>
        /// A claim error-related occurred.
        /// </summary>
        ClaimError = 0x20000000,

        /// <summary>
        /// A header error-related occurred.
        /// </summary>
        HeaderError = 0x10000000,

        /// <summary>
        /// A lifetime error-related occurred.
        /// </summary>
        LifetimeError = 0x08000000,

        /// <summary>
        /// A signature error-related occurred.
        /// </summary>
        SignatureError = 0x04000000,

        /// <summary>
        /// A decryption error occurred.
        /// </summary>
        DecryptionError = 0x02000000,

        /// <summary>
        /// A decompression error occurred.
        /// </summary>
        DecompressionError = 0x01000000,

        /// <summary>
        /// A duplication error occurred.
        /// </summary>
        DuplicationError = 0x00800000,

        /// <summary>
        /// A structural error occurred.
        /// </summary>
        StructuralError = 0x00400000,

        /// <summary>
        /// The token is not a JWT in compact representation, is not base64url encoded, and is not a JSON UTF-8 encoded.
        /// </summary>
        MalformedToken = StructuralError | 0x00000001,

        /// <summary>
        /// The signature is invalid.
        /// </summary>
        InvalidSignature = SignatureError | 0x00000001,

        /// <summary>
        /// The signature key is not found.
        /// </summary>
        SignatureKeyNotFound = SignatureError | KeyError | 0x00000002,

        /// <summary>
        /// The signature is not base64url encoded.
        /// </summary>
        MalformedSignature = SignatureError | StructuralError | 0x00000004,

        /// <summary>
        /// The signature is not present.
        /// </summary>
        MissingSignature = SignatureError | 0x00000008,

        /// <summary>
        /// The 'alg' header parameter is missing.
        /// </summary>
        MissingAlgorithm = SignatureError | HeaderError | 0x00000001,

        /// <summary>
        /// The 'alg' header parameter is not supported.
        /// </summary>
        NotSupportedAlgorithm = SignatureError | HeaderError | 0x00000002,

        /// <summary>
        /// The token was already validated previously.
        /// </summary>
        TokenReplayed = 0x00000001,

        /// <summary>
        /// The token has expired, according to the 'nbf' claim.
        /// </summary>
        Expired = ClaimError | LifetimeError | 0x00000001,

        /// <summary>
        /// The token is not yet valid, according to the 'nbf' claim.
        /// </summary>
        NotYetValid = ClaimError | LifetimeError | 0x00000002,

        /// <summary>
        /// The 'enc' header parameter is missing.
        /// </summary>
        MissingEncryptionAlgorithm = DecryptionError | HeaderError | 0x00000001,

        /// <summary>
        /// The token decryption has failed.
        /// </summary>
        DecryptionFailed = KeyError | DecryptionError | 0x00000001,

        /// <summary>
        /// The encryption key was not found.
        /// </summary>
        EncryptionKeyNotFound = KeyError | DecryptionError | 0x00000002,

        /// <summary>
        /// The token has an invalid claim.
        /// </summary>
        InvalidClaim = ClaimError | 0x00000001,

        /// <summary>
        /// The token has a missing claim.
        /// </summary>
        MissingClaim = ClaimError | 0x00000002,

        /// <summary>
        /// The token has an invalid header. 
        /// </summary>
        InvalidHeader = HeaderError | 0x00000001,

        /// <summary>
        /// The token has a missing header.
        /// </summary>
        MissingHeader = HeaderError | 0x00000002,

        /// <summary>
        /// The 'crit' header defines an unsupported header.
        /// </summary>
        CriticalHeaderUnsupported = HeaderError | 0x00000004,

        /// <summary>
        /// The 'crit' header defines a missing critical header.
        /// </summary>
        CriticalHeaderMissing = HeaderError | 0x00000008,

        /// <summary>
        /// The token decompression has failed.
        /// </summary>
        DecompressionFailed = DecompressionError | 0x00000001
    }
}