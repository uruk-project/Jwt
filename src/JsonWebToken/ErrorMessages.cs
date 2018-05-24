using System.Globalization;
using System.Runtime.Serialization;

namespace JsonWebToken
{
    /// <summary>
    /// Error messages.
    /// </summary>
    internal static class ErrorMessages
    {
        /// <summary>
        /// Formats the string using InvariantCulture
        /// </summary>
        /// <param name="format">Format string.</param>
        /// <param name="args">Format arguments.</param>
        /// <returns>Formatted string.</returns>
        public static string FormatInvariant(string format, params object[] args)
        {
            return string.Format(CultureInfo.InvariantCulture, format, args);
        }

        public const string MustBeGreaterThanZero = "{0} must be greater than zero. value: '{1}'.";
        public const string MustBeGreaterThanTimeSpanZero = "{0} must be greater than TimeSpan.Zero. value: '{1}'.";

        public const string MustNoBeNullIfRequired = "{0} is set to '{1}' but {2} is 'null' or empty.";
        public const string NotSupportedEncryptionAlgorithm = "Encryption failed. No support for: Algorithm: '{0}'.";
        public const string EncryptionFailed = "Encryption failed failed for: Algorithm: '{0}', key: '{1}'. See inner exception.";
        public const string NotSuportedAlgorithmForKeyWrap = "Key wrap is not supported for algorithm '{0}'.";

        public const string InvalidSymmetricKeySize = "Invalid key size. Valid key sizes are: 256, 384, and 512.";
        public const string InvalidEcdsaKeySize = "Invalid key size for '{0}. Valid key size must be '{1}' bits. Key size: '{2}'.";

        public const string AlgorithmRequireMinimumKeySize = "The algorithm '{0}' requires the a key size to be greater than '{1}' bits. Key size is '{2}'.";
        public const string MustBeAtLeast = "{0} must be at least '{1}'.";
        public const string SigningKeyTooSmall = "The key '{0}' for signing cannot be smaller than '{1}' bits. Key size: '{2}'.";
        public const string VerifyKeyTooSmall = "The key '{0}' for verifying cannot be smaller than '{1}' bits. Key size: '{2}'.";
        public const string EncryptionKeyTooSmall = "The key '{0}' for encryption with algorithm '{1}' cannot be smaller than '{2}' bits. Key size: '{3}'.";
        public const string KeyWrapKeySizeIncorrect = "Key wrap algorithm '{0}' requires a key of '{1}' bits. Key : '{2}', key size: '{3}'.";
        public const string NotSupportedSignatureAlgorithm = "Signature failed. No support for: Algorithm: '{0}', key: '{1}'.";
        public const string NotSupportedSignatureHashAlgorithm = "Signature failed. No support for: Algorithm: '{0}'.";
        public const string MissingPrivateKey = "The key '{0}' has no private key.";
        public const string NotSupportedUnwrap = "Key unwrap failed. Algorithm: '{0}'.";
        public const string NotSupportedCurve = "Elliptical Curve not supported for curveId: '{0}'";
        public const string NotSupportedAlgorithm = "The algorithm '{0}' is not supported.";
        public const string MalformedKey = "The key '{0}' is malformed.";
        public const string KeyWrapFailed = "Key wrapping failed";
        public const string CreateSymmetricAlgorithmFailed = "Failed to create symmetric algorithm for key wrap with key: '{0}', algorithm: '{1}'.";
        public const string KeySizeMustBeMultipleOf64 = "The length of the key to unwrap must be a multiple of 64 bits. The size is: '{0}' bits.";
        public const string NotAuthenticData = "Data is not authentic.";
        public const string NotSupportedKeyedHashAlgorithm = "Unable to create KeyedHashAlgorithm for algorithm '{0}'.";

        public const string InvalidRsaKey = "Invalid RSA key: '{0}'. Both modulus (N) and exponent (E) must be present.";

        public const string InvalidSize = "The value of '{0}' must be '{1}' bits, but was {2}.";
        public const string PayloadIncompatibleWithPlaintext = "The 'Plaintext' property is not compatible when a value is already defined within the 'Payload'.";
        public const string NotSupportedCertificate = "The certificate does not contains RSA key material or ECDsa key material.";
    }
}
