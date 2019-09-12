// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;
using JsonWebToken.Internal;

namespace JsonWebToken
{
    /// <summary>
    /// Error messages.
    /// </summary>
    [StackTraceHidden]
    internal static class ThrowHelper
    {
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static bool TryWriteError(out int bytesWritten)
        {
            bytesWritten = 0;
            return false;
        }

        [DoesNotReturn]
        internal static void ThrowInvalidOperationException_UnableToObtainKeysException(string address) => throw CreateInvalidOperationException_UnableToObtainKeysException(address);
        [MethodImpl(MethodImplOptions.NoInlining)]
        private static Exception CreateInvalidOperationException_UnableToObtainKeysException(string address) => new InvalidOperationException($"Unable to obtain keys from: '{address}'");

        [DoesNotReturn]
        internal static void ThrowArgumentException_RequireHttpsException(string address) => throw CreateArgumentException_RequireHttpsException(address);
        [MethodImpl(MethodImplOptions.NoInlining)]
        private static Exception CreateArgumentException_RequireHttpsException(string address) => new ArgumentException($"The address specified '{address}' is not valid as per HTTPS scheme.", nameof(address));

        [DoesNotReturn]
        internal static void ThrowArgumentException_MustNotContainNull(ExceptionArgument argument) => throw CreateArgumentException_MustNotContainNull(argument);
        [MethodImpl(MethodImplOptions.NoInlining)]
        private static Exception CreateArgumentException_MustNotContainNull(ExceptionArgument argument) => new ArgumentException($"The collection must not contains a 'null' value.", GetArgumentName(argument));

        [DoesNotReturn]
        internal static void ThrowArgumentOutOfRangeException_NeedNonNegNum(ExceptionArgument argument) => throw CreateArgumentOutOfRangeException_NeedNonNegNum(argument);
        [MethodImpl(MethodImplOptions.NoInlining)]
        private static Exception CreateArgumentOutOfRangeException_NeedNonNegNum(ExceptionArgument argument) => new ArgumentOutOfRangeException(GetArgumentName(argument), "Non-negative number required.");

        [DoesNotReturn]
        internal static void ThrowArgumentNullException(ExceptionArgument argument) => throw CreateArgumentNullException(argument);
        [MethodImpl(MethodImplOptions.NoInlining)]
        private static Exception CreateArgumentNullException(ExceptionArgument argument) => new ArgumentNullException(GetArgumentName(argument));

        [DoesNotReturn]
        internal static void ThrowInvalidOperationException_PolicyBuilderRequireSignature() => throw CreateInvalidOperationException_PolicyBuilderRequireSignature();
        [MethodImpl(MethodImplOptions.NoInlining)]
        private static Exception CreateInvalidOperationException_PolicyBuilderRequireSignature() => new InvalidOperationException($"Signature validation must be either defined by calling the method '{nameof(TokenValidationPolicyBuilder.RequireSignature)}' or explicitly ignored by calling the '{nameof(TokenValidationPolicyBuilder.AcceptUnsecureToken)}' method.");

        [DoesNotReturn]
        internal static void ThrowJwtDescriptorException_ClaimIsRequired(ReadOnlySpan<byte> claim) => throw CreateJwtDescriptorException_ClaimIsRequired(claim);
        [MethodImpl(MethodImplOptions.NoInlining)]
        private static Exception CreateJwtDescriptorException_ClaimIsRequired(ReadOnlySpan<byte> claim)
        {
#if NETSTANDARD2_0 || NET461
            var value = EncodingHelper.GetUtf8String(claim);
#else
            var value = Encoding.UTF8.GetString(claim);
#endif
            return new JwtDescriptorException($"The claim '{value}' is required.");
        }

        [DoesNotReturn]
        internal static void ThrowJwtDescriptorException_ClaimMustBeOfType(ReadOnlySpan<byte> utf8Name, JwtTokenType[] types) => throw CreateJwtDescriptorException_ClaimMustBeOfType(utf8Name, types);
        [MethodImpl(MethodImplOptions.NoInlining)]
        private static Exception CreateJwtDescriptorException_ClaimMustBeOfType(ReadOnlySpan<byte> utf8Name, JwtTokenType[] types)
        {
            var claimTypes = string.Join(", ", types.Select(t => t.ToString()));
#if NETSTANDARD2_0 || NET461
            var value = EncodingHelper.GetUtf8String(utf8Name);
#else
            var value = Encoding.UTF8.GetString(utf8Name);
#endif
            return new JwtDescriptorException($"The claim '{value}' must be of type [{claimTypes}].");
        }

        [DoesNotReturn]
        internal static void ThrowJwtDescriptorException_ClaimMustBeOfType(ReadOnlySpan<byte> utf8Name, JwtTokenType type) => throw CreateJwtDescriptorException_ClaimMustBeOfType(utf8Name, type);
        [MethodImpl(MethodImplOptions.NoInlining)]
        private static Exception CreateJwtDescriptorException_ClaimMustBeOfType(ReadOnlySpan<byte> utf8Name, JwtTokenType type)
        {
#if NETSTANDARD2_0 || NET461
            var value = EncodingHelper.GetUtf8String(utf8Name);
#else
            var value = Encoding.UTF8.GetString(utf8Name);
#endif
            return new JwtDescriptorException($"The claim '{value}' must be of type {type}.");
        }

        [DoesNotReturn]
        internal static void ThrowJwtDescriptorException_HeaderMustBeOfType(ReadOnlySpan<byte> utf8Name, JwtTokenType[] types) => throw CreateJwtDescriptorException_HeaderMustBeOfType(utf8Name, types);
        [MethodImpl(MethodImplOptions.NoInlining)]
        private static Exception CreateJwtDescriptorException_HeaderMustBeOfType(ReadOnlySpan<byte> utf8Name, JwtTokenType[] types)
        {
            var claimTypes = string.Join(", ", types.Select(t => t.ToString()));
#if NETSTANDARD2_0 || NET461
            var value = EncodingHelper.GetUtf8String(utf8Name);
#else
            var value = Encoding.UTF8.GetString(utf8Name);
#endif
            return new JwtDescriptorException($"The header parameter '{value}' must be of type [{claimTypes}].");
        }

        [DoesNotReturn]
        internal static void ThrowJwtDescriptorException_HeaderMustBeOfType(ReadOnlySpan<byte> utf8Name, JwtTokenType type) => throw CreateJwtDescriptorException_HeaderMustBeOfType(utf8Name, type);
        [MethodImpl(MethodImplOptions.NoInlining)]
        private static Exception CreateJwtDescriptorException_HeaderMustBeOfType(ReadOnlySpan<byte> utf8Name, JwtTokenType type)
        {
#if NETSTANDARD2_0 || NET461
            var value = EncodingHelper.GetUtf8String(utf8Name);
#else
            var value = Encoding.UTF8.GetString(utf8Name);
#endif
            return new JwtDescriptorException($"The header parameter '{value}' must be of type {type}.");
        }

        [DoesNotReturn]
        internal static void ThrowJwtDescriptorException_HeaderIsRequired(ReadOnlySpan<byte> header) => throw CreateJwtDescriptorException_HeaderIsRequired(header);
        [MethodImpl(MethodImplOptions.NoInlining)]
        private static Exception CreateJwtDescriptorException_HeaderIsRequired(ReadOnlySpan<byte> header)
        {
#if NETSTANDARD2_0 || NET461
            var value = EncodingHelper.GetUtf8String(header);
#else
            var value = Encoding.UTF8.GetString(header);
#endif
            return new JwtDescriptorException($"The header parameter '{value}' is required.");
        }

        [DoesNotReturn]
        internal static void ThrowInvalidOperationException_NoSigningKeyDefined() => throw CreateInvalidOperationException_NoSigningKeyDefined();
        [MethodImpl(MethodImplOptions.NoInlining)]
        private static Exception CreateInvalidOperationException_NoSigningKeyDefined() => new InvalidOperationException("No signing key is defined.");

        [DoesNotReturn]
        internal static void ThrowInvalidOperationException_ConcurrentOperationsNotSupported() => CreateInvalidOperationException_ConcurrentOperationsNotSupported();
        [MethodImpl(MethodImplOptions.NoInlining)]
        private static void CreateInvalidOperationException_ConcurrentOperationsNotSupported() => throw new InvalidOperationException("Operations that change non-concurrent collections must have exclusive access. A concurrent update was performed on this collection and corrupted its state. The collection's state is no longer correct.");

        [DoesNotReturn]
        internal static void ThrowArgumentOutOfRangeException_MustBeGreaterOrEqualToZero(ExceptionArgument argument, int value) => throw CreateArgumentOutOfRangeException_MustBeGreaterOrEqualToZero(argument, value);
        [MethodImpl(MethodImplOptions.NoInlining)]
        private static Exception CreateArgumentOutOfRangeException_MustBeGreaterOrEqualToZero(ExceptionArgument argument, int value) => new ArgumentOutOfRangeException(GetArgumentName(argument), $"{GetArgumentName(argument)} must be greater equal or zero. value: '{value}'.");

        [DoesNotReturn]
        internal static void ThrowInvalidOperationException_NotSupportedJsonType(JwtTokenType type) => throw CreateInvalidOperationException_NotSupportedJsonType(type);
        [MethodImpl(MethodImplOptions.NoInlining)]
        private static Exception CreateInvalidOperationException_NotSupportedJsonType(JwtTokenType type) => new InvalidOperationException($"The type {type} is not supported.");

        [DoesNotReturn]
        internal static void ThrowArgumentOutOfRangeException_MustBeGreaterThanZero(ExceptionArgument argument, int value) => throw CreateArgumentOutOfRangeException_MustBeGreaterThanZero(argument, value);
        [MethodImpl(MethodImplOptions.NoInlining)]
        private static Exception CreateArgumentOutOfRangeException_MustBeGreaterThanZero(ExceptionArgument argument, int value) => new ArgumentOutOfRangeException(GetArgumentName(argument), $"{nameof(value)} must be greater than zero. value: '{value}'.");

        [DoesNotReturn]
        internal static void ThrowArgumentOutOfRangeException_MustBeGreaterThanTimeSpanZero(ExceptionArgument argument, int value) => throw CreateArgumentOutOfRangeException_MustBeGreaterThanTimeSpanZero(argument, value);
        [MethodImpl(MethodImplOptions.NoInlining)]
        private static Exception CreateArgumentOutOfRangeException_MustBeGreaterThanTimeSpanZero(ExceptionArgument argument, int value) => new ArgumentOutOfRangeException($"{GetArgumentName(argument)} must be greater than TimeSpan.Zero. value: '{value}'.");

        [DoesNotReturn]
        internal static void ThrowNotSupportedException_EncryptionAlgorithm(EncryptionAlgorithm? algorithm) => throw CreateNotSupportedException_EncryptionAlgorithm(algorithm);
        [MethodImpl(MethodImplOptions.NoInlining)]
        private static Exception CreateNotSupportedException_EncryptionAlgorithm(EncryptionAlgorithm? algorithm) => new NotSupportedException($"Encryption failed. No support for: Algorithm: '{algorithm}'.");

        [DoesNotReturn]
        internal static void ThrowCryptographicException_EncryptionFailed(EncryptionAlgorithm? algorithm, Jwk key, Exception innerException) => throw CreateCryptographicException_EncryptionFailed(algorithm, key, innerException);
        [MethodImpl(MethodImplOptions.NoInlining)]
        private static Exception CreateCryptographicException_EncryptionFailed(EncryptionAlgorithm? algorithm, Jwk key, Exception innerException) => new CryptographicException($"Encryption failed for: Algorithm: '{algorithm}', key: '{key.Kid}'. See inner exception.", innerException);

        [DoesNotReturn]
        internal static void ThrowNotSupportedException_AlgorithmForKeyWrap(EncryptionAlgorithm? algorithm) => throw CreateNotSupportedException_AlgorithmForKeyWrap(algorithm);
        [MethodImpl(MethodImplOptions.NoInlining)]
        private static Exception CreateNotSupportedException_AlgorithmForKeyWrap(EncryptionAlgorithm? algorithm) => new NotSupportedException($"Key wrap is not supported for algorithm: '{algorithm}'.");

        [DoesNotReturn]
        internal static void ThrowNotSupportedException_AlgorithmForKeyWrap(KeyManagementAlgorithm? algorithm) => throw CreateNotSupportedException_AlgorithmForKeyWrap(algorithm);
        [MethodImpl(MethodImplOptions.NoInlining)]
        private static Exception CreateNotSupportedException_AlgorithmForKeyWrap(KeyManagementAlgorithm? algorithm) => new NotSupportedException($"Key wrap is not supported for algorithm: '{algorithm}'.");

        [DoesNotReturn]
        internal static void ThrowNotSupportedException_CompressionAlgorithm(CompressionAlgorithm compressionAlgorithm) => throw CreateNotSupportedException_CompressionAlgorithm(compressionAlgorithm);
        [MethodImpl(MethodImplOptions.NoInlining)]
        private static Exception CreateNotSupportedException_CompressionAlgorithm(CompressionAlgorithm compressionAlgorithm) => new NotSupportedException($"Compression algorithm: '{compressionAlgorithm.Name}' is not supported.");

        [DoesNotReturn]
        internal static void ThrowArgumentOutOfRangeException_InvalidEcdsaKeySize(Jwk key, SignatureAlgorithm algorithm, int validKeySize, int keySize) => throw CreateArgumentOutOfRangeException_InvalidEcdsaKeySize(key, algorithm, validKeySize, keySize);
        [MethodImpl(MethodImplOptions.NoInlining)]
        private static Exception CreateArgumentOutOfRangeException_InvalidEcdsaKeySize(Jwk key, SignatureAlgorithm algorithm, int validKeySize, int keySize) => new ArgumentOutOfRangeException(nameof(algorithm), $"Invalid key size for '{key.Kid}'. Valid key size must be '{validKeySize}' bits for the algorithm {algorithm}. Key size: '{keySize}'.");

        [DoesNotReturn]
        internal static void ThrowArgumentOutOfRangeException_AlgorithmRequireMinimumKeySize(Jwk key, string algorithm, int validKeySize, int keySize) => throw CreateArgumentOutOfRangeException_AlgorithmRequireMinimumKeySize(key, algorithm, validKeySize, keySize);
        [MethodImpl(MethodImplOptions.NoInlining)]
        private static Exception CreateArgumentOutOfRangeException_AlgorithmRequireMinimumKeySize(Jwk key, string algorithm, int validKeySize, int keySize) => new ArgumentOutOfRangeException(nameof(key.KeySizeInBits), $"The algorithm '{algorithm}' requires the a key size to be greater than '{validKeySize}' bits. Key size is '{keySize}'.");

        [DoesNotReturn]
        internal static void ThrowArgumentOutOfRangeException_WellKnowProperty(WellKnownProperty wellKnownName) => throw CreateArgumentOutOfRangeException_WellKnowProperty(wellKnownName);
        [MethodImpl(MethodImplOptions.NoInlining)]
        private static Exception CreateArgumentOutOfRangeException_WellKnowProperty(WellKnownProperty wellKnownName) => new ArgumentOutOfRangeException(nameof(wellKnownName), $"The property value '{wellKnownName}' is unknwon.");

        [DoesNotReturn]
        internal static void ThrowKeyNotFoundException() => throw CreateKeyNotFoundException();
        [MethodImpl(MethodImplOptions.NoInlining)]
        private static Exception CreateKeyNotFoundException() => new KeyNotFoundException();

        [DoesNotReturn]
        internal static void ThrowInvalidOperationException_MalformedJwks() => throw CreateInvalidOperationException_MalformedJwks();
        [MethodImpl(MethodImplOptions.NoInlining)]
        private static Exception CreateInvalidOperationException_MalformedJwks() => new InvalidOperationException("The JWKS is malformed.");

        [DoesNotReturn]
        internal static void ThrowArgumentOutOfRangeException_MustBeAtLeast(ExceptionArgument argument, int value) => throw CreateArgumentOutOfRangeException_MustBeAtLeast(argument, value);
        [MethodImpl(MethodImplOptions.NoInlining)]
        private static Exception CreateArgumentOutOfRangeException_MustBeAtLeast(ExceptionArgument argument, int value) => new ArgumentOutOfRangeException(nameof(value), $"{GetArgumentName(argument)} must be at least '{value}'.");

        [DoesNotReturn]
        internal static void ThrowArgumentOutOfRangeException_SigningKeyTooSmall(Jwk key, int minimalValue) => throw CreateArgumentOutOfRangeException_SigningKeyTooSmall(key, minimalValue);
        [MethodImpl(MethodImplOptions.NoInlining)]
        private static Exception CreateArgumentOutOfRangeException_SigningKeyTooSmall(Jwk key, int minimalValue) => new ArgumentOutOfRangeException(nameof(key.KeySizeInBits), $"The key '{key.Kid}' for signing cannot be smaller than '{minimalValue}' bits. Key size: '{key.KeySizeInBits}'.");

        [DoesNotReturn]
        internal static void ThrowArgumentOutOfRangeException_EncryptionKeyTooSmall(Jwk key, EncryptionAlgorithm algorithm, int minimalValue, int currentKeySize) => throw CreateArgumentOutOfRangeException_EncryptionKeyTooSmall(key, algorithm, minimalValue, currentKeySize);
        [MethodImpl(MethodImplOptions.NoInlining)]
        private static Exception CreateArgumentOutOfRangeException_EncryptionKeyTooSmall(Jwk key, EncryptionAlgorithm algorithm, int minimalValue, int currentKeySize) => new ArgumentOutOfRangeException(nameof(key.KeySizeInBits), $"The key '{key.Kid}' for encryption with algorithm '{algorithm}' cannot be smaller than '{minimalValue}' bits. Key size: '{currentKeySize}'.");

        [DoesNotReturn]
        internal static void ThrowArgumentOutOfRangeException_KeyWrapKeySizeIncorrect(KeyManagementAlgorithm algorithm, int requiredValue, Jwk key, int currentKeySize) => throw CreateArgumentOutOfRangeException_KeyWrapKeySizeIncorrect(algorithm, requiredValue, key, currentKeySize);
        [MethodImpl(MethodImplOptions.NoInlining)]
        private static Exception CreateArgumentOutOfRangeException_KeyWrapKeySizeIncorrect(KeyManagementAlgorithm algorithm, int requiredValue, Jwk key, int currentKeySize) => new ArgumentOutOfRangeException(nameof(key), $"The key '{key.Kid}' for key wrapping with algorithm '{algorithm}' must be of '{requiredValue}' bits. Key size: '{currentKeySize}'.");

        [DoesNotReturn]
        internal static void ThrowNotSupportedException_SignatureAlgorithm(SignatureAlgorithm algorithm, Jwk? key) => throw CreateNotSupportedException_SignatureAlgorithm(algorithm, key);
        [MethodImpl(MethodImplOptions.NoInlining)]
        private static Exception CreateNotSupportedException_SignatureAlgorithm(SignatureAlgorithm algorithm, Jwk? key) => new NotSupportedException($"Signature failed. No support for: Algorithm: '{algorithm}', key: '{key?.Kid}'.");

        [DoesNotReturn]
        internal static void ThrowNotSupportedException_Jwk(ReadOnlySpan<byte> name) => throw CreateNotSupportedException_Jwk(name);
        [MethodImpl(MethodImplOptions.NoInlining)]
        private static Exception CreateNotSupportedException_Jwk(ReadOnlySpan<byte> name) => new NotSupportedException($"JWK type '{Encoding.UTF8.GetString(name.ToArray())}' is not supported.");

        [DoesNotReturn]
        internal static void ThrowNotSupportedException_SignatureAlgorithm(SignatureAlgorithm? algorithm) => throw CreateNotSupportedException_SignatureAlgorithm(algorithm);
        [MethodImpl(MethodImplOptions.NoInlining)]
        private static Exception CreateNotSupportedException_SignatureAlgorithm(SignatureAlgorithm? algorithm) => new NotSupportedException($"Signature failed. No support for: Algorithm: '{algorithm}'.");

        [DoesNotReturn]
        internal static void ThrowNotSupportedException_Curve(string curve) => throw CreateNotSupportedException_Curve(curve);
        [MethodImpl(MethodImplOptions.NoInlining)]
        private static Exception CreateNotSupportedException_Curve(string curve) => new NotSupportedException($"Elliptical Curve not supported for curve: '{curve}'");

        [DoesNotReturn]
        internal static void ThrowNotSupportedException_Algorithm(string algorithm) => throw CreateNotSupportedException_Algorithm(algorithm);
        [MethodImpl(MethodImplOptions.NoInlining)]
        private static Exception CreateNotSupportedException_Algorithm(string algorithm) => new NotSupportedException($"The algorithm '{algorithm}' is not supported.");

        [DoesNotReturn]
        internal static void ThrowArgumentException_MalformedKey() => throw CreateArgumentException_MalformedKey();
        [MethodImpl(MethodImplOptions.NoInlining)]
        private static Exception CreateArgumentException_MalformedKey() => new ArgumentException("The key is malformed.");

        [DoesNotReturn]
        internal static void ThrowCryptographicException_KeyWrapFailed() => throw CreateCryptographicException_KeyWrapFailed();
        [MethodImpl(MethodImplOptions.NoInlining)]
        private static Exception CreateCryptographicException_KeyWrapFailed() => new CryptographicException("Key wrapping failed.");

        [DoesNotReturn]
        internal static void ThrowCryptographicException_CreateSymmetricAlgorithmFailed(Jwk key, KeyManagementAlgorithm algorithm, Exception innerException) => throw CreateCryptographicException_CreateSymmetricAlgorithmFailed(key, algorithm, innerException);
        [MethodImpl(MethodImplOptions.NoInlining)]
        private static Exception CreateCryptographicException_CreateSymmetricAlgorithmFailed(Jwk key, KeyManagementAlgorithm algorithm, Exception innerException) => new CryptographicException($"Failed to create symmetric algorithm for key wrap with key: '{key.Kid}', algorithm: '{algorithm}'.", innerException);

        [DoesNotReturn]
        internal static void ThrowArgumentException_KeySizeMustBeMultipleOf64(ReadOnlySpan<byte> keyBytes) => throw CreateArgumentException_KeySizeMustBeMultipleOf64(keyBytes);
        [MethodImpl(MethodImplOptions.NoInlining)]
        private static Exception CreateArgumentException_KeySizeMustBeMultipleOf64(ReadOnlySpan<byte> keyBytes) => new ArgumentException($"The length of the key to unwrap must be a multiple of 64 bits. The size is: '{keyBytes.Length << 3}' bits.", nameof(keyBytes));

        [DoesNotReturn]
        internal static void ThrowNotSupportedException_KeyedHashAlgorithm(SignatureAlgorithm algorithm) => throw CreateNotSupportedException_KeyedHashAlgorithm(algorithm);
        [MethodImpl(MethodImplOptions.NoInlining)]
        private static Exception CreateNotSupportedException_KeyedHashAlgorithm(SignatureAlgorithm algorithm) => new NotSupportedException($"Unable to create hash algorithm for algorithm '{algorithm}'.");

        [DoesNotReturn]
        internal static void ThrowArgumentException_InvalidRsaKey(Jwk key) => throw CreateArgumentException_InvalidRsaKey(key);
        [MethodImpl(MethodImplOptions.NoInlining)]
        private static Exception CreateArgumentException_InvalidRsaKey(Jwk key) => new ArgumentException($"Invalid RSA key: '{key.Kid}'. Both modulus (N) and exponent (E) must be present.", nameof(key));

        [DoesNotReturn]
        internal static void ThrowArgumentException_DestinationTooSmall(int size, int requiredSize) => throw CreateArgumentException_DestinationTooSmall(size, requiredSize);
        [MethodImpl(MethodImplOptions.NoInlining)]
        private static Exception CreateArgumentException_DestinationTooSmall(int size, int requiredSize) => new ArgumentException($"destination is too small. Required: {requiredSize}. Current: {size}.", "destination");

        [DoesNotReturn]
        internal static void ThrowArgumentException_StaticKeyNotSupported() => throw CreateArgumentException_StaticKeyNotSupported();
        [MethodImpl(MethodImplOptions.NoInlining)]
        private static Exception CreateArgumentException_StaticKeyNotSupported() => new ArgumentException("DIrect encryption does not support the use of static key.", "staticKey");

        [DoesNotReturn]
        internal static void ThrowInvalidOperationException_InvalidCertificate() => throw CreateInvalidOperationException_InvalidCertificate();
        [MethodImpl(MethodImplOptions.NoInlining)]
        private static Exception CreateInvalidOperationException_InvalidCertificate() => new InvalidOperationException("The certificate does not contains RSA key material or ECDsa key material.");

        [DoesNotReturn]
        internal static void ThrowObjectDisposedException(Type type) => throw CreateObjectDisposedException(type);
        [MethodImpl(MethodImplOptions.NoInlining)]
        private static Exception CreateObjectDisposedException(Type type) => new ObjectDisposedException(type.ToString());

        [DoesNotReturn]
        internal static void ThrowArgumentOutOfRangeException() => throw CreateArgumentOutOfRangeException();
        [MethodImpl(MethodImplOptions.NoInlining)]
        private static ArgumentOutOfRangeException CreateArgumentOutOfRangeException() => new ArgumentOutOfRangeException("name");

        [DoesNotReturn]
        internal static void ThrowFormatException_MalformdedInput(int inputLength) => throw CreateFormatException_MalformdedInput(inputLength);
        [MethodImpl(MethodImplOptions.NoInlining)]
        private static FormatException CreateFormatException_MalformdedInput(int inputLength) => new FormatException($"Malformed input: {inputLength} is an invalid input length.");

        [DoesNotReturn]
        internal static void ThrowOperationNotDoneException(OperationStatus status) => throw CreateOperationNotDoneException(status);
        [MethodImpl(MethodImplOptions.NoInlining)]
        private static Exception CreateOperationNotDoneException(OperationStatus status)
        {
            switch (status)
            {
                case OperationStatus.DestinationTooSmall:
                    return new InvalidOperationException("The destination buffer is too small.");
                case OperationStatus.InvalidData:
                    return new FormatException("The input is not a valid Base-64 URL string as it contains a non-base 64 character.");
                default:
                    throw new InvalidOperationException();
            }
        }

        [DoesNotReturn]
        internal static void ThrowFormatException_NotSupportedNumberValue(ReadOnlySpan<byte> name) => throw CreateFormatException_NotSUpportedNumberValue(name);
        [MethodImpl(MethodImplOptions.NoInlining)]
        private static Exception CreateFormatException_NotSUpportedNumberValue(ReadOnlySpan<byte> name) => new FormatException($"The claim '{Encoding.UTF8.GetString(name.ToArray())}' is not a supported Number value.");

        [DoesNotReturn]
        internal static string ThrowFormatException_MalformedJson() => throw CreateFormatException_MalformedJson();
        [MethodImpl(MethodImplOptions.NoInlining)]
        private static Exception CreateFormatException_MalformedJson() => new FormatException("The JSON is malformed.");

        [DoesNotReturn]
        internal static string ThrowFormatException_MalformedJson(string message) => throw CreateFormatException_MalformedJson(message);
        [MethodImpl(MethodImplOptions.NoInlining)]
        private static Exception CreateFormatException_MalformedJson(string message) => new FormatException("The JSON is malformed. " + message);

        private static string GetArgumentName(ExceptionArgument argument)
        {
            switch (argument)
            {
                case ExceptionArgument.value: return "value";
                case ExceptionArgument.name: return "name";
                case ExceptionArgument.compressor: return "compressor";
                case ExceptionArgument.key: return "key";
                case ExceptionArgument.d: return "d";
                case ExceptionArgument.x: return "x";
                case ExceptionArgument.y: return "y";
                case ExceptionArgument.signatureFactory: return "signatureFactory";
                case ExceptionArgument.keyWrapFactory: return "keyWrapFactory";
                case ExceptionArgument.authenticatedEncryptionFactory: return "authenticatedEncryptionFactory";
                case ExceptionArgument.encryptionAlgorithm: return "encryptionAlgorithm";
                case ExceptionArgument.plaintext: return "plaintext";
                case ExceptionArgument.associatedData: return "associatedData";
                case ExceptionArgument.ciphertext: return "ciphertext";
                case ExceptionArgument.nonce: return "nonce";
                case ExceptionArgument.authenticationTag: return "authenticationTag";
                case ExceptionArgument.data: return "data";
                case ExceptionArgument.signature: return "signature";
                case ExceptionArgument.policy: return "policy";
                case ExceptionArgument.values: return "values";
                case ExceptionArgument.claim: return "claim";
                case ExceptionArgument.header: return "header";
                case ExceptionArgument.algorithm: return "algorithm";
                case ExceptionArgument.certificate: return "certificate";
                case ExceptionArgument.keys: return "keys";
                case ExceptionArgument.json: return "json";
                case ExceptionArgument.nestedToken: return "nestedToken";
                case ExceptionArgument.encryptionKey: return "encryptionKey";
                case ExceptionArgument.payload: return "payload";
                case ExceptionArgument.encryptionKeyProviders: return "encryptionKeyProviders";
                case ExceptionArgument.signerFactory: return "signerFactory";
                case ExceptionArgument.keyWrapperFactory: return "keyWrapperFactory";
                case ExceptionArgument.authenticatedEncryptorFactory: return "authenticatedEncryptorFactory";
                case ExceptionArgument.token: return "token";
                case ExceptionArgument.dp: return "dp";
                case ExceptionArgument.dq: return "dq";
                case ExceptionArgument.q: return "q";
                case ExceptionArgument.qi: return "qi";
                case ExceptionArgument.p: return "p";
                case ExceptionArgument.e: return "e";
                case ExceptionArgument.n: return "n";
                case ExceptionArgument.jwt: return "jwt";
                case ExceptionArgument.jwk: return "jwk";
                case ExceptionArgument.jwks: return "jwks";
                case ExceptionArgument.bytes: return "bytes";
                case ExceptionArgument.k: return "k";
                case ExceptionArgument.count: return "count";
                case ExceptionArgument.clockSkew: return "clockSkew";
                case ExceptionArgument.size: return "size";
                case ExceptionArgument.capacity: return "capacity";
                case ExceptionArgument.base64url: return "base64url";
                case ExceptionArgument.descriptor: return "descriptor";
                case ExceptionArgument.context: return "context";

                default:
                    Debug.Fail("The enum value is not defined, please check the ExceptionArgument Enum.");
                    return "";
            }
        }
    }

    internal enum ExceptionArgument
    {
        value,
        name,
        compressor,
        key,
        d,
        x,
        y,
        signatureFactory,
        keyWrapFactory,
        authenticatedEncryptionFactory,
        encryptionAlgorithm,
        plaintext,
        associatedData,
        ciphertext,
        nonce,
        authenticationTag,
        data,
        signature,
        policy,
        values,
        claim,
        header,
        algorithm,
        certificate,
        keys,
        json,
        nestedToken,
        encryptionKey,
        payload,
        encryptionKeyProviders,
        signerFactory,
        keyWrapperFactory,
        authenticatedEncryptorFactory,
        token,
        dp,
        dq,
        q,
        qi,
        p,
        e,
        n,
        jwt,
        jwk,
        jwks,
        bytes,
        k,
        count,
        clockSkew,
        size,
        capacity,
        base64url,
        descriptor,
        context
    }
}
