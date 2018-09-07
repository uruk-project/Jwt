namespace JsonWebToken
{
    public enum TokenValidationStatus
    {
        Success,

        /// <summary>
        /// The token is not a JWT in compact representation, is not base64url encoded, and is not a JSON UTF-8 encoded.
        /// </summary>
        MalformedToken,

        /// <summary>
        /// The signature is invalid.
        /// </summary>
        InvalidSignature,

        /// <summary>
        /// The signature key is not found.
        /// </summary>
        SignatureKeyNotFound,

        /// <summary>
        /// The signature is not base64url encoded.
        /// </summary>
        MalformedSignature,

        /// <summary>
        /// The signature is not present.
        /// </summary>
        MissingSignature,

        /// <summary>
        /// The token was already validated previously.
        /// </summary>
        TokenReplayed,

        /// <summary>
        /// The token has expired, according to the 'nbf' claim.
        /// </summary>
        Expired,

        /// <summary>
        /// The 'enc' header parameter is missing.
        /// </summary>
        MissingEncryptionAlgorithm,

        /// <summary>
        /// The token decryption has failed.
        /// </summary>
        DecryptionFailed,

        /// <summary>
        /// The token is not yeet valid, according to the 'nbf' claim.
        /// </summary>
        NotYetValid,

        /// <summary>
        /// hee token has an invalid claim.
        /// </summary>
        InvalidClaim,

        /// <summary>
        /// The token has an missing claim.
        /// </summary>
        MissingClaim,
        InvalidHeader,
        MissingHeader,
        DecompressionFailed,
        EncryptionKeyNotFound
    }
}