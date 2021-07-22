// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text.Json;
using JsonWebToken.Cryptography;

namespace JsonWebToken
{
    /// <summary>Error messages.</summary>
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
        internal static void ThrowArgumentException_RequireHttpsException(string address) => throw CreateArgumentException_RequireHttpsException(address);
        [MethodImpl(MethodImplOptions.NoInlining)]
        private static Exception CreateArgumentException_RequireHttpsException(string address) => new ArgumentException($"The address specified '{address}' is not valid as per HTTPS scheme.", nameof(address));

        [DoesNotReturn]
        internal static void ThrowArgumentNullException(ExceptionArgument argument) => throw CreateArgumentNullException(argument);
        [MethodImpl(MethodImplOptions.NoInlining)]
        private static Exception CreateArgumentNullException(ExceptionArgument argument) => new ArgumentNullException(GetArgumentName(argument));

        [DoesNotReturn]
        internal static void ThrowInvalidOperationException_PolicyBuilderRequireSignature() => throw CreateInvalidOperationException_PolicyBuilderRequireSignature();
        [MethodImpl(MethodImplOptions.NoInlining)]
        private static Exception CreateInvalidOperationException_PolicyBuilderRequireSignature() => new InvalidOperationException($"Signature validation must be either defined by calling the method '{nameof(TokenValidationPolicyBuilder.RequireSignature)}' or explicitly ignored by calling the '{nameof(TokenValidationPolicyBuilder.AcceptUnsecureToken)}' method.");

        [DoesNotReturn]
        internal static void ThrowJwtDescriptorException_SecEventAttributeIsRequired(JsonEncodedText claim) => throw CreateJwtDescriptorException_SecEventAttributeIsRequired(claim);
        [MethodImpl(MethodImplOptions.NoInlining)]
        private static Exception CreateJwtDescriptorException_SecEventAttributeIsRequired(JsonEncodedText claim) => new JwtDescriptorException($"The claim '{claim}' is required.");

        [DoesNotReturn]
        internal static void ThrowJwtDescriptorException_SecEventAttributeMustBeOfType(JsonEncodedText utf8Name, JwtValueKind type) => throw CreateJwtDescriptorException_SecEventAttributeMustBeOfType(utf8Name, type);
        [MethodImpl(MethodImplOptions.NoInlining)]
        private static Exception CreateJwtDescriptorException_SecEventAttributeMustBeOfType(JsonEncodedText utf8Name, JwtValueKind type) => new JwtDescriptorException($"The claim '{utf8Name}' must be of type {type}.");

        [DoesNotReturn]
        internal static void ThrowJwtDescriptorException_SecEventAttributeMustBeOfType(JsonEncodedText utf8Name, JwtValueKind[] types) => throw CreateJwtDescriptorException_SecEventAttributeMustBeOfType(utf8Name, types);
        [MethodImpl(MethodImplOptions.NoInlining)]
        private static Exception CreateJwtDescriptorException_SecEventAttributeMustBeOfType(JsonEncodedText utf8Name, JwtValueKind[] types)
        {
            var claimTypes = string.Join(", ", types.Select(t => t.ToString()));
            return new JwtDescriptorException($"The claim '{utf8Name}' must be of type [{claimTypes}].");
        }

        [DoesNotReturn]
        internal static void ThrowJwtDescriptorException_ClaimIsRequired(JsonEncodedText claim) => throw CreateJwtDescriptorException_ClaimIsRequired(claim);
        [MethodImpl(MethodImplOptions.NoInlining)]
        private static Exception CreateJwtDescriptorException_ClaimIsRequired(JsonEncodedText claim) => new JwtDescriptorException($"The claim '{claim}' is required.");

        [DoesNotReturn]
        internal static void ThrowJwtDescriptorException_ClaimMustBeOfType(JsonEncodedText utf8Name, JwtValueKind[] types) => throw CreateJwtDescriptorException_ClaimMustBeOfType(utf8Name, types);
        [MethodImpl(MethodImplOptions.NoInlining)]
        private static Exception CreateJwtDescriptorException_ClaimMustBeOfType(JsonEncodedText utf8Name, JwtValueKind[] types)
        {
            var claimTypes = string.Join(", ", types.Select(t => t.ToString()));
            return new JwtDescriptorException($"The claim '{utf8Name}' must be of type [{claimTypes}].");
        }

        [DoesNotReturn]
        internal static void ThrowJwtDescriptorException_ClaimMustBeOfType(JsonEncodedText utf8Name, JwtValueKind type) => throw CreateJwtDescriptorException_ClaimMustBeOfType(utf8Name, type);
        [MethodImpl(MethodImplOptions.NoInlining)]
        private static Exception CreateJwtDescriptorException_ClaimMustBeOfType(JsonEncodedText utf8Name, JwtValueKind type) => new JwtDescriptorException($"The claim '{utf8Name}' must be of type {type}.");

        [DoesNotReturn]
        internal static void ThrowJwtDescriptorException_HeaderMustBeOfType(JsonEncodedText utf8Name, JwtValueKind[] types) => throw CreateJwtDescriptorException_HeaderMustBeOfType(utf8Name, types);
        [MethodImpl(MethodImplOptions.NoInlining)]
        private static Exception CreateJwtDescriptorException_HeaderMustBeOfType(JsonEncodedText utf8Name, JwtValueKind[] types)
        {
            var claimTypes = string.Join(", ", types.Select(t => t.ToString()));
            return new JwtDescriptorException($"The header parameter '{utf8Name}' must be of type [{claimTypes}].");
        }

        [DoesNotReturn]
        internal static void ThrowJwtDescriptorException_HeaderMustBeOfType(JsonEncodedText utf8Name, JwtValueKind type) => throw CreateJwtDescriptorException_HeaderMustBeOfType(utf8Name, type);
        [MethodImpl(MethodImplOptions.NoInlining)]
        private static Exception CreateJwtDescriptorException_HeaderMustBeOfType(JsonEncodedText utf8Name, JwtValueKind type) => new JwtDescriptorException($"The header parameter '{utf8Name}' must be of type {type}.");

        [DoesNotReturn]
        internal static void ThrowJwtDescriptorException_HeaderIsRequired(JsonEncodedText header) => throw CreateJwtDescriptorException_HeaderIsRequired(header);
        [MethodImpl(MethodImplOptions.NoInlining)]
        private static Exception CreateJwtDescriptorException_HeaderIsRequired(JsonEncodedText header) => new JwtDescriptorException($"The header parameter '{header}' is required.");

        [DoesNotReturn]
        internal static void ThrowInvalidOperationException_ConcurrentOperationsNotSupported() => throw CreateInvalidOperationException_ConcurrentOperationsNotSupported();
        [MethodImpl(MethodImplOptions.NoInlining)]
        private static Exception CreateInvalidOperationException_ConcurrentOperationsNotSupported() => new InvalidOperationException("Operations that change non-concurrent collections must have exclusive access. A concurrent update was performed on this collection and corrupted its state. The collection's state is no longer correct.");
        
        [DoesNotReturn]
        internal static void ThrowInvalidOperationException_AlreadyInitialized(ExceptionArgument argument) => throw CreateInvalidOperationException_AlreadyInitialized(argument);
        [MethodImpl(MethodImplOptions.NoInlining)]
        private static Exception CreateInvalidOperationException_AlreadyInitialized(ExceptionArgument argument) => new InvalidOperationException($"The property '{argument}' is already initialized. You cannot set more than once this property.");
        
        [DoesNotReturn]
        internal static void ThrowInvalidOperationException_NotInitialized(ExceptionArgument argument) => throw CreateInvalidOperationException_NotInitialized(argument);
        [MethodImpl(MethodImplOptions.NoInlining)]
        private static Exception CreateInvalidOperationException_NotInitialized(ExceptionArgument argument) => new InvalidOperationException($"The '{argument}' property is not initialized. You must set a value before to use it.");

        [DoesNotReturn]
        internal static void ThrowArgumentOutOfRangeException_MustBeGreaterOrEqualToZero(ExceptionArgument argument, int value) => throw CreateArgumentOutOfRangeException_MustBeGreaterOrEqualToZero(argument, value);
        [MethodImpl(MethodImplOptions.NoInlining)]
        private static Exception CreateArgumentOutOfRangeException_MustBeGreaterOrEqualToZero(ExceptionArgument argument, int value) => new ArgumentOutOfRangeException(GetArgumentName(argument), $"{GetArgumentName(argument)} must be greater or equal to zero. value: '{value}'.");
        
        [DoesNotReturn]
        internal static void ThrowInvalidOperationException_NotSupportedJsonType(JwtValueKind type) => throw CreateInvalidOperationException_NotSupportedJsonType(type);
        [MethodImpl(MethodImplOptions.NoInlining)]
        internal static Exception CreateInvalidOperationException_NotSupportedJsonType(JwtValueKind type) => new InvalidOperationException($"The type {type} is not supported.");
        internal static Exception CreateInvalidOperationException_NotSupportedJsonType(JsonTokenType type) => new InvalidOperationException($"The type {type} is not supported.");

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
        internal static Exception CreateNotSupportedException_EncryptionAlgorithm(EncryptionAlgorithm? algorithm) => new NotSupportedException($"Encryption failed. No support for: Algorithm: '{algorithm}'.");

        [DoesNotReturn]
        internal static void ThrowCryptographicException_EncryptionFailed(EncryptionAlgorithm? algorithm, Jwk key, Exception innerException) => throw CreateCryptographicException_EncryptionFailed(algorithm, key, innerException);
        [MethodImpl(MethodImplOptions.NoInlining)]
        private static Exception CreateCryptographicException_EncryptionFailed(EncryptionAlgorithm? algorithm, Jwk key, Exception innerException) => new CryptographicException($"Encryption failed for: Algorithm: '{algorithm}', key: '{key.Kid}'. See inner exception.", innerException);

        [DoesNotReturn]
        internal static void ThrowJsonElementWrongType_InvalidOperationException(JsonTokenType expectedTokenType, JsonTokenType tokenType) => throw CreateJsonElementWrongType_InvalidOperationException(expectedTokenType, tokenType);
        [MethodImpl(MethodImplOptions.NoInlining)]
        private static Exception CreateJsonElementWrongType_InvalidOperationException(JsonTokenType expectedTokenType, JsonTokenType tokenType) => new InvalidOperationException($"The requested operation requires an element of type '{expectedTokenType}', but the target element has type '{tokenType}'.");

        [DoesNotReturn]
        internal static void ThrowNotSupportedException_AlgorithmForKeyWrap(EncryptionAlgorithm? algorithm, Jwk key) => throw CreateNotSupportedException_AlgorithmForKeyWrap(algorithm, key);
        [MethodImpl(MethodImplOptions.NoInlining)]
        private static Exception CreateNotSupportedException_AlgorithmForKeyWrap(EncryptionAlgorithm? algorithm, Jwk key) => new NotSupportedException($"Key wrap is not supported for algorithm: '{algorithm}' with a key of type '{key.Kty}' and size of {key.KeySizeInBits} bits.");

        [DoesNotReturn]
        internal static void ThrowNotSupportedException_AlgorithmForKeyWrap(KeyManagementAlgorithm? algorithm) => throw CreateNotSupportedException_AlgorithmForKeyWrap(algorithm);
        [MethodImpl(MethodImplOptions.NoInlining)]
        internal static Exception CreateNotSupportedException_AlgorithmForKeyWrap(KeyManagementAlgorithm? algorithm) => new NotSupportedException($"Key wrap is not supported for algorithm: '{algorithm}'.");
        
        [DoesNotReturn]
        internal static void ThrowNotSupportedException_AlgorithmForKeyWrap(AlgorithmId algorithm) => throw CreateNotSupportedException_AlgorithmForKeyWrap(algorithm);
        [MethodImpl(MethodImplOptions.NoInlining)]
        internal static Exception CreateNotSupportedException_AlgorithmForKeyWrap(AlgorithmId algorithm) => new NotSupportedException($"Key wrap is not supported for algorithm: '{algorithm}'.");

        [DoesNotReturn]
        internal static void ThrowArgumentOutOfRangeException_InvalidEcdsaKeySize(Jwk key, SignatureAlgorithm algorithm, int validKeySize, int keySize) => throw CreateArgumentOutOfRangeException_InvalidEcdsaKeySize(key, algorithm, validKeySize, keySize);
        [MethodImpl(MethodImplOptions.NoInlining)]
        private static Exception CreateArgumentOutOfRangeException_InvalidEcdsaKeySize(Jwk key, SignatureAlgorithm algorithm, int validKeySize, int keySize) => new ArgumentOutOfRangeException(nameof(algorithm), $"Invalid key size for '{key.Kid}'. Valid key size must be '{validKeySize}' bits for the algorithm {algorithm}. Key size: '{keySize}'.");

        [DoesNotReturn]
        internal static void ThrowArgumentOutOfRangeException_AlgorithmRequireMinimumKeySize(int keySizeInBits, string algorithm, int validKeySize) => throw CreateArgumentOutOfRangeException_AlgorithmRequireMinimumKeySize(keySizeInBits, algorithm, validKeySize);
        [MethodImpl(MethodImplOptions.NoInlining)]
        private static Exception CreateArgumentOutOfRangeException_AlgorithmRequireMinimumKeySize(int keySizeInBits, string algorithm, int validKeySize) => new ArgumentOutOfRangeException(nameof(keySizeInBits), $"The algorithm '{algorithm}' requires the a key size to be greater than '{validKeySize}' bits. Key size is '{keySizeInBits}'.");

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
        private static Exception CreateArgumentOutOfRangeException_SigningKeyTooSmall(Jwk key, int minimalValue) => new ArgumentOutOfRangeException(nameof(key), key.Kid.EncodedUtf8Bytes.IsEmpty ? $"The signing key cannot be smaller than '{minimalValue}' bits. Key size: '{key.KeySizeInBits}'." : $"The signing key '{key.Kid}' cannot be smaller than '{minimalValue}' bits. Key size: '{key.KeySizeInBits}'.");

        [DoesNotReturn]
        internal static void ThrowArgumentOutOfRangeException_EncryptionKeyTooSmall(EncryptionAlgorithm algorithm, int minimalValue, int currentKeySize) => throw CreateArgumentOutOfRangeException_EncryptionKeyTooSmall(algorithm, minimalValue, currentKeySize);
        [MethodImpl(MethodImplOptions.NoInlining)]
        private static Exception CreateArgumentOutOfRangeException_EncryptionKeyTooSmall(EncryptionAlgorithm algorithm, int minimalValue, int currentKeySize) => new ArgumentOutOfRangeException("key", $"The key for encryption with algorithm '{algorithm}' cannot be smaller than '{minimalValue}' bits. Key size: '{currentKeySize}'.");

        [DoesNotReturn]
        internal static void ThrowNotSupportedException_SignatureAlgorithm(SignatureAlgorithm algorithm, Jwk? key) => throw CreateNotSupportedException_SignatureAlgorithm(algorithm, key);
        [MethodImpl(MethodImplOptions.NoInlining)]
        private static Exception CreateNotSupportedException_SignatureAlgorithm(SignatureAlgorithm algorithm, Jwk? key) => new NotSupportedException($"Signature failed. No support for: Algorithm: '{algorithm}', key: '{key?.Kid}'.");

        [DoesNotReturn]
        internal static void ThrowNotSupportedException_Algorithm(SignatureAlgorithm algorithm) => throw CreateNotSupportedException_Algorithm(algorithm);
        [MethodImpl(MethodImplOptions.NoInlining)]
        internal static Exception CreateNotSupportedException_Algorithm(SignatureAlgorithm algorithm) => new NotSupportedException($"The algorithm '{algorithm}' is not supported for this kind of JWK.");

        [DoesNotReturn]
        internal static void ThrowNotSupportedException_Algorithm(AlgorithmId algorithm) => throw CreateNotSupportedException_Algorithm(algorithm);
        [MethodImpl(MethodImplOptions.NoInlining)]
        internal static Exception CreateNotSupportedException_Algorithm(AlgorithmId algorithm) => new NotSupportedException($"The algorithm '{algorithm}' is not supported.");

        [DoesNotReturn]
        internal static void ThrowNotSupportedException_Algorithm(KeyManagementAlgorithm algorithm) => throw CreateNotSupportedException_Algorithm(algorithm);
        [MethodImpl(MethodImplOptions.NoInlining)]
        private static Exception CreateNotSupportedException_Algorithm(KeyManagementAlgorithm algorithm) => new NotSupportedException($"The algorithm '{algorithm}' is not supported for this kind of JWK.");

        [DoesNotReturn]
        internal static void ThrowNotSupportedException_Jwk(ReadOnlySpan<byte> name) => throw CreateNotSupportedException_Jwk(name);
        [MethodImpl(MethodImplOptions.NoInlining)]
        private static Exception CreateNotSupportedException_Jwk(ReadOnlySpan<byte> name) => new NotSupportedException($"JWK type '{Utf8.GetString(name)}' is not supported.");

#if SUPPORT_ELLIPTIC_CURVE
        [DoesNotReturn]
        internal static void ThrowNotSupportedException_SignatureAlgorithm(SignatureAlgorithm? algorithm, in EllipticalCurve curve) => throw CreateNotSupportedException_SignatureAlgorithm(algorithm, curve);
        [MethodImpl(MethodImplOptions.NoInlining)]
        private static Exception CreateNotSupportedException_SignatureAlgorithm(SignatureAlgorithm? algorithm, in EllipticalCurve curve) => new NotSupportedException($"Signature failed. No support for: Algorithm: '{algorithm}' with curve '{curve}'.");
#endif

        [DoesNotReturn]
        internal static void ThrowNotSupportedException_Curve(string? curve) => throw CreateNotSupportedException_Curve(curve);
        [MethodImpl(MethodImplOptions.NoInlining)]
        internal static Exception CreateNotSupportedException_Curve(string? curve) => new NotSupportedException($"Elliptical Curve not supported for curve: '{curve}'");

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
        internal static void ThrowArgumentException_KeySizeMustBeMultipleOf64(ReadOnlySpan<byte> keyBytes) => throw CreateArgumentException_KeySizeMustBeMultipleOf64(keyBytes);
        [MethodImpl(MethodImplOptions.NoInlining)]
        private static Exception CreateArgumentException_KeySizeMustBeMultipleOf64(ReadOnlySpan<byte> keyBytes) => new ArgumentException($"The length of the key to unwrap must be a multiple of 64 bits. The size is: '{keyBytes.Length << 3}' bits.", nameof(keyBytes));

        [DoesNotReturn]
        internal static void ThrowInvalidOperationException_UnexpectedKeyType(Jwk key, string expectedType) => throw CreateInvalidOperationException_UnexpectedKeyType(key, expectedType);
        [MethodImpl(MethodImplOptions.NoInlining)]
        private static Exception CreateInvalidOperationException_UnexpectedKeyType(Jwk key, string expectedType) => new InvalidOperationException($"Unexpected key type: '{key.Kty}'. Expected a key of type '{expectedType}'.");

        [DoesNotReturn]
        internal static void ThrowArgumentException_DestinationTooSmall(int size, int requiredSize) => throw CreateArgumentException_DestinationTooSmall(size, requiredSize);
        [MethodImpl(MethodImplOptions.NoInlining)]
        private static Exception CreateArgumentException_DestinationTooSmall(int size, int requiredSize) => new ArgumentException($"destination is too small. Required: {requiredSize}. Current: {size}.", "destination");

        [DoesNotReturn]
        internal static void ThrowInvalidOperationException_InvalidCertificate() => throw CreateInvalidOperationException_InvalidCertificate();
        [MethodImpl(MethodImplOptions.NoInlining)]
        private static Exception CreateInvalidOperationException_InvalidCertificate() => new InvalidOperationException("The certificate does not contains RSA key material or ECDsa key material.");

        [DoesNotReturn]
        internal static void ThrowObjectDisposedException(Type type) => throw CreateObjectDisposedException(type);
        [MethodImpl(MethodImplOptions.NoInlining)]
        private static Exception CreateObjectDisposedException(Type type) => new ObjectDisposedException(type.ToString());

        [DoesNotReturn]
        internal static void ThrowArgumentOutOfRangeException(string name) => throw CreateArgumentOutOfRangeException(name);
        [MethodImpl(MethodImplOptions.NoInlining)]
        private static ArgumentOutOfRangeException CreateArgumentOutOfRangeException(string name) => new ArgumentOutOfRangeException(name);

        [DoesNotReturn]
        internal static void ThrowFormatException_MalformdedInput(int inputLength) => throw CreateFormatException_MalformdedInput(inputLength);
        [MethodImpl(MethodImplOptions.NoInlining)]
        private static FormatException CreateFormatException_MalformdedInput(int inputLength) => new FormatException($"Malformed input: {inputLength} is an invalid input length.");

        [DoesNotReturn]
        internal static void ThrowOperationNotDoneException(OperationStatus status) => throw CreateOperationNotDoneException(status);
        [MethodImpl(MethodImplOptions.NoInlining)]
        private static Exception CreateOperationNotDoneException(OperationStatus status)
        {
            return status switch
            {
                OperationStatus.DestinationTooSmall => new InvalidOperationException("The destination buffer is too small."),
                OperationStatus.InvalidData => new FormatException("The input is not a valid Base-64 URL string as it contains a non-base 64 character."),
                _ => throw new InvalidOperationException(),
            };
        }

        [DoesNotReturn]
        internal static string ThrowFormatException_MalformedJson() => throw CreateFormatException_MalformedJson();
        [MethodImpl(MethodImplOptions.NoInlining)]
        internal static Exception CreateFormatException_MalformedJson() => new FormatException("The JSON is malformed.");

        [DoesNotReturn]
        internal static string ThrowFormatException_MalformedJson(string message) => throw CreateFormatException_MalformedJson(message);
        [MethodImpl(MethodImplOptions.NoInlining)]
        private static Exception CreateFormatException_MalformedJson(string message) => new FormatException("The JSON is malformed. " + message);

        [DoesNotReturn]
        internal static void ThrowArgumentException_PrependMustBeLessOrEqualToBlockSize(ReadOnlySpan<byte> prepend, int blockSize) => throw CreateArgumentException_PrependMustBeLessOrEqualToBlockSize(prepend, blockSize);
        [MethodImpl(MethodImplOptions.NoInlining)]
        private static Exception CreateArgumentException_PrependMustBeLessOrEqualToBlockSize(ReadOnlySpan<byte> prepend, int blockSize) => new ArgumentException($"The length of the prepend must be of the same size than the block size, or less. Prepend length is: '{prepend.Length}' bytes, block size is: {blockSize}.", nameof(prepend));

        [DoesNotReturn]
        internal static void ThrowInvalidOperationException_InvalidPem() => throw CreateInvalidOperationException_InvalidPem();
        [MethodImpl(MethodImplOptions.NoInlining)]
        private static Exception CreateInvalidOperationException_InvalidPem() => new InvalidOperationException("The PEM-encoded key is invalid.");

        private static string GetArgumentName(ExceptionArgument argument)
        {
            switch (argument)
            {
                case ExceptionArgument.value: return "value";
                case ExceptionArgument.name: return "name";
                case ExceptionArgument.compressor: return "compressor";
                case ExceptionArgument.decompressor: return "decompressor";
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
                case ExceptionArgument.signingKey: return "signingKey";
                case ExceptionArgument.encryptionKey: return "encryptionKey";
                case ExceptionArgument.payload: return "payload";
                case ExceptionArgument.decryptionKeyProviders: return "decryptionKeyProviders";
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
                case ExceptionArgument.saltSizeInBytes: return "saltSizeInBytes";
                case ExceptionArgument.capacity: return "capacity";
                case ExceptionArgument.base64: return "base64";
                case ExceptionArgument.base64url: return "base64url";
                case ExceptionArgument.descriptor: return "descriptor";
                case ExceptionArgument.context: return "context";
                case ExceptionArgument.inner: return "inner";
                case ExceptionArgument.sha: return "sha";
                case ExceptionArgument.passphrase: return "passphrase";

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
        decompressor,
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
        signingKey,
        encryptionKey,
        payload,
        decryptionKeyProviders,
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
        saltSizeInBytes,
        capacity,
        base64,
        base64url,
        descriptor,
        context,
        inner,
        sha,
        passphrase
    }
}
