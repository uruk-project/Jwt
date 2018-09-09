using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System.Collections.Generic;
using System.Linq;

namespace JsonWebToken
{
    /// <summary>
    /// Error messages.
    /// </summary>
    internal static class ErrorMessages
    {
        public static string UnableToObtainKeys(string address)
        {
            return $"Unable to obtain keys from: '{address}'";
        }

        internal static string RequireHttps(string address)
        {
            return $"The address specified '{address}' is not valid as per HTTPS scheme.";
        }

        internal static string UnexpectedTokenParsingDate(JsonToken tokenType)
        {
            return $"Unexpected token parsing date. Expected {nameof(JsonToken.Integer)}, got {tokenType}";
        }

        internal static string PolicyBuilderRequireSignature()
        {
            return $"Signature validation must be either defined by calling the method '{nameof(TokenValidationPolicyBuilder.RequireSignature)}' or explicitly ignored by calling the '{nameof(TokenValidationPolicyBuilder.AcceptUnsecureToken)}' method.";
        }

        internal static string ClaimIsRequired(string claim)
        {
            return $"The claim '{claim}' is required.";
        }

        internal static string ClaimIsProhibited(string claim)
        {
            return $"The claim '{claim}' is prohibited.";
        }

        internal static string ClaimMustBeOfType(KeyValuePair<string, JTokenType[]> claim)
        {
            var claimTypes = string.Join(", ", claim.Value.Select(t => t.ToString()));
            return $"The claim '{claim.Key}' must be of type[{claimTypes}].";
        }

        internal static string HeaderMustBeOfType(KeyValuePair<string, JTokenType[]> header)
        {
            var claimTypes = string.Join(", ", header.Value.Select(t => t.ToString()));
            return $"The header parameter '{header.Key}' must be of type[{claimTypes}].";
        }

        internal static string HeaderIsRequired(string header)
        {
            return $"The header parameter '{header}' is required.";
        }

        internal static string MustBeGreaterThanZero(string name, int currentValue)
        {
            return $"{name} must be greater than zero. value: '{currentValue}'.";
        }

        internal static string MustBeGreaterThanTimeSpanZero(string name, int currentValue)
        {
            return $"{name} must be greater than TimeSpan.Zero. value: '{currentValue}'.";
        }

        internal static string NotSupportedEncryptionAlgorithm(EncryptionAlgorithm algorithm)
        {
            return $"Encryption failed. No support for: Algorithm: '{algorithm.Name}'.";
        }

        internal static string EncryptionFailed(EncryptionAlgorithm algorithm, JsonWebKey key)
        {
            return $"Encryption failed for: Algorithm: '{algorithm.Name}', key: '{key.Kid}'. See inner exception.";
        }

        internal static string NotSuportedAlgorithmForKeyWrap(EncryptionAlgorithm algorithm)
        {
            return $"Key wrap is not supported for algorithm: '{algorithm.Name}'.";
        }

        internal static string NotSuportedAlgorithmForKeyWrap(KeyManagementAlgorithm algorithm)
        {
            return $"Key wrap is not supported for algorithm: '{algorithm.Name}'.";
        }

        internal static string NotSupportedCompressionAlgorithm(string compressionAlgorithm)
        {
            return $"Compression algorithm: '{compressionAlgorithm}' is not supported.";
        }

        internal static string InvalidEcdsaKeySize(JsonWebKey key, int validKeySize, int keySize)
        {
            return $"Invalid key size for '{key.Kid}'. Valid key size must be '{validKeySize}' bits. Key size: '{keySize}'.";
        }

        internal static string AlgorithmRequireMinimumKeySize(string algorithm, int validKeySize, int keySize)
        {
            return $"The algorithm '{algorithm}' requires the a key size to be greater than '{validKeySize}' bits. Key size is '{keySize}'.";
        }

        internal static string MustBeAtLeast(string name, int value)
        {
            return $"{name} must be at least '{value}'.";
        }

        internal static string SigningKeyTooSmall(JsonWebKey key, int minimalValue, int currentKeySize)
        {
            return $"The key '{key.Kid}' for signing cannot be smaller than '{minimalValue}' bits. Key size: '{currentKeySize}'.";
        }

        internal static string VerifyKeyTooSmall(JsonWebKey key, int minimalValue, int currentKeySize)
        {
            return $"The key '{key.Kid}' for verifying cannot be smaller than '{minimalValue}' bits. Key size: '{currentKeySize}'.";
        }

        internal static string EncryptionKeyTooSmall(JsonWebKey key, EncryptionAlgorithm algorithm, int minimalValue, int currentKeySize)
        {
            return $"The key '{key.Kid}' for encryption with algorithm '{algorithm.Name}' cannot be smaller than '{minimalValue}' bits. Key size: '{currentKeySize}'.";
        }

        internal static string KeyWrapKeySizeIncorrect(KeyManagementAlgorithm algorithm, int requiredValue, JsonWebKey key, int currentKeySize)
        {
            return $"The key '{key.Kid}' for key wrapping with algorithm '{algorithm.Name}' must be of '{requiredValue}' bits. Key size: '{currentKeySize}'.";
        }

        internal static string NotSupportedSignatureAlgorithm(SignatureAlgorithm algorithm, JsonWebKey key)
        {
            return $"Signature failed. No support for: Algorithm: '{algorithm.Name}', key: '{key.Kid}'.";
        }

        internal static string NotSupportedSignatureAlgorithm(SignatureAlgorithm algorithm)
        {
            return $"Signature failed. No support for: Algorithm: '{algorithm.Name}'.";
        }

        internal static string MissingPrivateKey(JsonWebKey key)
        {
            return $"The key '{key.Kid}' has no private key.";
        }

        internal static string NotSupportedUnwrap(KeyManagementAlgorithm algorithm)
        {
            return $"Key unwrap failed. No support for: Algorithm: '{algorithm.Name}'.";
        }

        internal static string NotSupportedCurve(string curveId)
        {
            return $"Elliptical Curve not supported for curveId: '{curveId}'";
        }

        internal static string NotSupportedAlgorithm(string algorithm)
        {
            return $"The algorithm '{algorithm}' is not supported.";
        }

        internal static string MalformedKey(JsonWebKey key)
        {
            return $"The key '{key.Kid}' is malformed.";
        }

        internal static string KeyWrapFailed()
        {
            return "Key wrapping failed.";
        }

        internal static string CreateSymmetricAlgorithmFailed(JsonWebKey key, KeyManagementAlgorithm algorithm)
        {
            return $"Failed to create symmetric algorithm for key wrap with key: '{key.Kid}', algorithm: '{algorithm.Name}'.";
        }

        internal static string KeySizeMustBeMultipleOf64(int keySize)
        {
            return $"The length of the key to unwrap must be a multiple of 64 bits. The size is: '{keySize}' bits.";
        }

        internal static string NotAuthenticData()
        {
            return "Data is not authentic.";
        }

        internal static string NotSupportedKeyedHashAlgorithm(SignatureAlgorithm algorithm)
        {
            return $"Unable to create hash algorithm for algorithm '{algorithm.Name}'.";
        }

        internal static string InvalidRsaKey(JsonWebKey key)
        {
            return $"Invalid RSA key: '{key.Kid}'. Both modulus (N) and exponent (E) must be present.";
        }

        internal static string InvalidCertificate()
        {
            return "The certificate does not contains RSA key material or ECDsa key material.";
        }
    }
}
