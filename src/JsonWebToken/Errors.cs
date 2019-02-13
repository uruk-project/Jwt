// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

using JsonWebToken.Internal;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace JsonWebToken
{
    /// <summary>
    /// Error messages.
    /// </summary>
    internal static class Errors
    {
        internal static bool TryWriteError(out int bytesWritten)
        {
            bytesWritten = 0;
            return false;
        }

        internal static void ThrowUnableToObtainKeys(string address)
        {
            throw new InvalidOperationException($"Unable to obtain keys from: '{address}'");
        }

        internal static void ThrowRequireHttps(string address)
        {
            throw new ArgumentException($"The address specified '{address}' is not valid as per HTTPS scheme.", nameof(address));
        }

        internal static Exception ThrowArgumentNullException(string argumentName)
        {
            throw new ArgumentNullException(argumentName);
        }

        internal static void ThrowPolicyBuilderRequireSignature()
        {
            throw new InvalidOperationException($"Signature validation must be either defined by calling the method '{nameof(TokenValidationPolicyBuilder.RequireSignature)}' or explicitly ignored by calling the '{nameof(TokenValidationPolicyBuilder.AcceptUnsecureToken)}' method.");
        }

        internal static void ThrowClaimIsRequired(ReadOnlySpan<byte> claim)
        {
#if NETSTANDARD2_0
            var value = EncodingHelper.GetUtf8String(claim);
#else
            var value = Encoding.UTF8.GetString(claim);
#endif
            throw new JwtDescriptorException($"The claim '{value}' is required.");
        }

        internal static void ThrowClaimIsProhibited(ReadOnlyMemory<byte> claim)
        {
            var value =
#if NETSTANDARD2_0
                EncodingHelper.GetUtf8String(claim.Span);
#else
                Encoding.UTF8.GetString(claim.Span);
#endif
            throw new JwtDescriptorException($"The claim '{value}' is prohibited.");
        }

        internal static void ThrowClaimMustBeOfType(ReadOnlySpan<byte> utf8Name, JwtTokenType[] types)
        {
            var claimTypes = string.Join(", ", types.Select(t => t.ToString()));
#if NETSTANDARD2_0
            var value = EncodingHelper.GetUtf8String(utf8Name);
#else
            var value = Encoding.UTF8.GetString(utf8Name);
#endif
            throw new JwtDescriptorException($"The claim '{value}' must be of type [{claimTypes}].");
        }

        internal static void ThrowClaimMustBeOfType(ReadOnlySpan<byte> utf8Name, JwtTokenType type)
        {
#if NETSTANDARD2_0
            var value = EncodingHelper.GetUtf8String(utf8Name);
#else
            var value = Encoding.UTF8.GetString(utf8Name);
#endif
            throw new JwtDescriptorException($"The claim '{value}' must be of type {type}.");
        }

        internal static void ThrowCannotAdvanceBuffer()
        {
            throw new InvalidOperationException("Cannot advance past the end of the buffer.");
        }

        internal static void ThrowHeaderMustBeOfType(ReadOnlySpan<byte> utf8Name, JwtTokenType[] types)
        {
            var claimTypes = string.Join(", ", types.Select(t => t.ToString()));
#if NETSTANDARD2_0
            var value = EncodingHelper.GetUtf8String(utf8Name);
#else
            var value = Encoding.UTF8.GetString(utf8Name);
#endif
            throw new JwtDescriptorException($"The header parameter '{value}' must be of type [{claimTypes}].");
        }

        internal static void ThrowHeaderMustBeOfType(ReadOnlySpan<byte> utf8Name, JwtTokenType type)
        {
#if NETSTANDARD2_0
            var value = EncodingHelper.GetUtf8String(utf8Name);
#else
            var value = Encoding.UTF8.GetString(utf8Name);
#endif
            throw new JwtDescriptorException($"The header parameter '{value}' must be of type {type}.");
        }

        internal static void ThrowNoSigningKeyDefined()
        {
            throw new InvalidOperationException("No signing key is defined.");
        }

        internal static void ThrowArgument(string argumentName)
        {
            throw new ArgumentException(argumentName);
        }

        internal static void ThrowHeaderIsRequired(ReadOnlySpan<byte> header)
        {
            var value =
#if NETSTANDARD2_0
                EncodingHelper.GetUtf8String(header);
#else
                Encoding.UTF8.GetString(header);
#endif
            throw new JwtDescriptorException($"The header parameter '{value}' is required.");
        }

        internal static void ThrowMustBeGreaterOrEqualToZero(string name, int value)
        {
            throw new ArgumentOutOfRangeException(name, $"{nameof(value)} must be greater equal or zero. value: '{value}'.");
        }

        internal static void ThrowNotSupportedJsonType(JwtTokenType type)
        {
            new InvalidOperationException($"The type {type} is not supported.");
        }

        internal static void ThrowMustBeGreaterThanZero(string name, int value)
        {
            throw new ArgumentOutOfRangeException(name, $"{nameof(value)} must be greater than zero. value: '{value}'.");
        }

        internal static void ThrowMustBeGreaterThanTimeSpanZero(string name, int value)
        {
            throw new ArgumentOutOfRangeException($"{name} must be greater than TimeSpan.Zero. value: '{value}'.");
        }

        internal static void ThrowNotSupportedEncryptionAlgorithm(EncryptionAlgorithm algorithm)
        {
            throw new NotSupportedException($"Encryption failed. No support for: Algorithm: '{algorithm}'.");
        }

        internal static void ThrowEncryptionFailed(EncryptionAlgorithm algorithm, Jwk key, Exception innerException)
        {
            throw new CryptographicException($"Encryption failed for: Algorithm: '{algorithm}', key: '{key.Kid}'. See inner exception.", innerException);
        }

        internal static void ThrowNotSuportedAlgorithmForKeyWrap(EncryptionAlgorithm algorithm)
        {
            throw new NotSupportedException($"Key wrap is not supported for algorithm: '{algorithm}'.");
        }

        internal static void ThrowNotSupportedAlgorithmForKeyWrap(KeyManagementAlgorithm algorithm)
        {
            throw new NotSupportedException($"Key wrap is not supported for algorithm: '{algorithm}'.");
        }

        internal static void ThrowNotSupportedCompressionAlgorithm(string compressionAlgorithm)
        {
            throw new NotSupportedException($"Compression algorithm: '{compressionAlgorithm}' is not supported.");
        }

        internal static void ThrowInvalidEcdsaKeySize(Jwk key, SignatureAlgorithm algorithm, int validKeySize, int keySize)
        {
            throw new ArgumentOutOfRangeException(nameof(algorithm), $"Invalid key size for '{key.Kid}'. Valid key size must be '{validKeySize}' bits for the algorithm {algorithm}. Key size: '{keySize}'.");
        }

        internal static void ThrowAlgorithmRequireMinimumKeySize(Jwk key, string algorithm, int validKeySize, int keySize)
        {
            throw new ArgumentOutOfRangeException(nameof(key.KeySizeInBits), $"The algorithm '{algorithm}' requires the a key size to be greater than '{validKeySize}' bits. Key size is '{keySize}'.");
        }

        internal static void ThrowMalformedJwks()
        {
            throw new InvalidOperationException("The JWKS is malformed.");
        }

        internal static void ThrowMustBeAtLeast(string name, int value)
        {
            throw new ArgumentOutOfRangeException(nameof(value), $"{name} must be at least '{value}'.");
        }

        internal static void ThrowSigningKeyTooSmall(Jwk key, int minimalValue)
        {
            throw new ArgumentOutOfRangeException(nameof(key.KeySizeInBits), $"The key '{key.Kid}' for signing cannot be smaller than '{minimalValue}' bits. Key size: '{key.KeySizeInBits}'.");
        }

        internal static void ThrowEncryptionKeyTooSmall(Jwk key, EncryptionAlgorithm algorithm, int minimalValue, int currentKeySize)
        {
            throw new ArgumentOutOfRangeException(nameof(key.KeySizeInBits), $"The key '{key.Kid}' for encryption with algorithm '{algorithm}' cannot be smaller than '{minimalValue}' bits. Key size: '{currentKeySize}'.");
        }

        internal static void ThrowKeyWrapKeySizeIncorrect(KeyManagementAlgorithm algorithm, int requiredValue, Jwk key, int currentKeySize)
        {
            throw new ArgumentOutOfRangeException(nameof(key), $"The key '{key.Kid}' for key wrapping with algorithm '{algorithm}' must be of '{requiredValue}' bits. Key size: '{currentKeySize}'.");
        }

        internal static void ThrowNotSupportedSignatureAlgorithm(SignatureAlgorithm algorithm, Jwk key)
        {
            throw new NotSupportedException($"Signature failed. No support for: Algorithm: '{algorithm}', key: '{key.Kid}'.");
        }

        internal static void ThrowNotSupportedJwk(string keyType)
        {
            throw new NotSupportedException($"JWK type '{keyType}' is not supported.");
        }

        internal static void ThrowNotSupportedSignatureAlgorithm(SignatureAlgorithm algorithm)
        {
            throw new NotSupportedException($"Signature failed. No support for: Algorithm: '{algorithm}'.");
        }

        internal static void ThrowMissingPrivateKey(Jwk key)
        {
            throw new InvalidOperationException($"The key '{key.Kid}' has no private key.");
        }

        internal static void ThrowNotSupportedUnwrap(KeyManagementAlgorithm algorithm)
        {
            throw new NotSupportedException($"Key unwrap failed. No support for: Algorithm: '{algorithm}'.");
        }
        
        internal static void ThrowNotSupportedCurve(string curve)
        {
            throw new NotSupportedException($"Elliptical Curve not supported for curve: '{curve}'");
        }

        internal static void ThrowNotSupportedAlgorithm(string algorithm)
        {
            throw new NotSupportedException($"The algorithm '{algorithm}' is not supported.");
        }

        internal static void ThrowMalformedKey(Jwk key)
        {
            throw new ArgumentException($"The key '{key.Kid}' is malformed.", nameof(key));
        }

        internal static void ThrowMalformedKey()
        {
            throw new ArgumentException("The key is malformed.");
        }

        internal static void ThrowKeyWrapFailed()
        {
            throw new CryptographicException("Key wrapping failed.");
        }

        internal static void ThrowCreateSymmetricAlgorithmFailed(Jwk key, KeyManagementAlgorithm algorithm, Exception innerException)
        {
            throw new CryptographicException($"Failed to create symmetric algorithm for key wrap with key: '{key.Kid}', algorithm: '{algorithm}'.", innerException);
        }

        internal static void ThrowKeySizeMustBeMultipleOf64(ReadOnlySpan<byte> keyBytes)
        {
            throw new ArgumentException($"The length of the key to unwrap must be a multiple of 64 bits. The size is: '{keyBytes.Length << 3}' bits.", nameof(keyBytes));
        }

        internal static void ThrowNotSupportedKeyedHashAlgorithm(SignatureAlgorithm algorithm)
        {
            throw new NotSupportedException($"Unable to create hash algorithm for algorithm '{algorithm}'.");
        }

        internal static void ThrowInvalidRsaKey(Jwk key)
        {
            throw new ArgumentException($"Invalid RSA key: '{key.Kid}'. Both modulus (N) and exponent (E) must be present.", nameof(key));
        }

        internal static void ThrowInvalidCertificate()
        {
            throw new InvalidOperationException("The certificate does not contains RSA key material or ECDsa key material.");
        }

        internal static void ThrowObjectDisposed(Type type)
        {
            throw new ObjectDisposedException(type.ToString());
        }

        internal static void ThrowFormatException()
        {
            throw new FormatException();
        }
    }
}
