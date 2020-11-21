// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using JsonWebToken.Cryptography;

namespace JsonWebToken
{
    internal static class JwtReaderHelper
    {
        internal static bool TryDecryptToken(
            List<SymmetricJwk> keys,
            ReadOnlySpan<byte> rawHeader,
            ReadOnlySpan<byte> rawCiphertext,
            ReadOnlySpan<byte> rawInitializationVector,
            ReadOnlySpan<byte> rawAuthenticationTag,
            EncryptionAlgorithm encryptionAlgorithm,
            Span<byte> decryptedBytes,
            out int bytesWritten)
        {
            int ciphertextLength = Base64Url.GetArraySizeRequiredToDecode(rawCiphertext.Length);
            int initializationVectorLength = Base64Url.GetArraySizeRequiredToDecode(rawInitializationVector.Length);
            int authenticationTagLength = Base64Url.GetArraySizeRequiredToDecode(rawAuthenticationTag.Length);
            int headerLength = rawHeader.Length;
            int bufferLength = ciphertextLength + headerLength + initializationVectorLength + authenticationTagLength;
            byte[]? arrayToReturn = null;
            Span<byte> buffer = bufferLength < Constants.MaxStackallocBytes
                ? stackalloc byte[bufferLength]
                : (arrayToReturn = ArrayPool<byte>.Shared.Rent(bufferLength));

            Span<byte> ciphertext = buffer.Slice(0, ciphertextLength);
            Span<byte> header = buffer.Slice(ciphertextLength, headerLength);
            Span<byte> initializationVector = buffer.Slice(ciphertextLength + headerLength, initializationVectorLength);
            Span<byte> authenticationTag = buffer.Slice(ciphertextLength + headerLength + initializationVectorLength, authenticationTagLength);
            try
            {
                Base64Url.Decode(rawCiphertext, ciphertext, out int _, out int ciphertextBytesWritten);
                Debug.Assert(ciphertext.Length == ciphertextBytesWritten);

                char[]? headerArrayToReturn = null;
                try
                {
                    int utf8HeaderLength = Utf8.GetMaxCharCount(header.Length);
                    Span<char> utf8Header = utf8HeaderLength < Constants.MaxStackallocBytes
                        ? stackalloc char[utf8HeaderLength]
                        : (headerArrayToReturn = ArrayPool<char>.Shared.Rent(utf8HeaderLength));

                    utf8HeaderLength = Utf8.GetChars(rawHeader, utf8Header);
                    Ascii.GetBytes(utf8Header.Slice(0, utf8HeaderLength), header);
                }
                finally
                {
                    if (headerArrayToReturn != null)
                    {
                        ArrayPool<char>.Shared.Return(headerArrayToReturn);
                    }
                }

                Base64Url.Decode(rawInitializationVector, initializationVector, out int _, out int ivBytesWritten);
                Debug.Assert(initializationVector.Length == ivBytesWritten);

                Base64Url.Decode(rawAuthenticationTag, authenticationTag, out int _, out int authenticationTagBytesWritten);
                Debug.Assert(authenticationTag.Length == authenticationTagBytesWritten);

                bytesWritten = 0;
                var decryptor = encryptionAlgorithm.Decryptor;

                for (int i = 0; i < keys.Count; i++)
                {
                    var key = keys[i];
                    if (decryptor.TryDecrypt(
                        key.K,
                        ciphertext,
                        header,
                        initializationVector,
                        authenticationTag,
                        decryptedBytes,
                        out bytesWritten))
                    {
                        return true;
                    }
                }

                return false;
            }
            finally
            {
                if (arrayToReturn != null)
                {
                    ArrayPool<byte>.Shared.Return(arrayToReturn);
                }
            }
        }

        public static bool TryGetContentEncryptionKeys(JwtHeaderDocument header, ReadOnlySpan<byte> rawEncryptedKey, EncryptionAlgorithm enc, IKeyProvider[] encryptionKeyProviders, [NotNullWhen(true)] out List<SymmetricJwk>? keys)
        {
            var alg = header.Alg;
            if (alg.IsEmpty)
            {
                keys = null;
                return false;
            }
            else if (alg.ValueEquals(KeyManagementAlgorithm.Direct.Utf8Name))
            {
                keys = new List<SymmetricJwk>(1);
                for (int i = 0; i < encryptionKeyProviders.Length; i++)
                {
                    var keySet = encryptionKeyProviders[i].GetKeys(header);
                    for (int j = 0; j < keySet.Length; j++)
                    {
                        var key = keySet[j];
                        if (key is SymmetricJwk symJwk && symJwk.CanUseForKeyWrapping(alg))
                        {
                            keys.Add(symJwk);
                        }
                    }
                }
            }
            else
            {
                if (KeyManagementAlgorithm.TryParse(alg, out var algorithm))
                {
                    int decodedSize = Base64Url.GetArraySizeRequiredToDecode(rawEncryptedKey.Length);

                    byte[]? encryptedKeyToReturnToPool = null;
                    byte[]? unwrappedKeyToReturnToPool = null;
                    Span<byte> encryptedKey = decodedSize <= Constants.MaxStackallocBytes ?
                        stackalloc byte[decodedSize] :
                        encryptedKeyToReturnToPool = ArrayPool<byte>.Shared.Rent(decodedSize);

                    try
                    {
                        var operationResult = Base64Url.Decode(rawEncryptedKey, encryptedKey, out _, out int bytesWritten);
                        Debug.Assert(operationResult == OperationStatus.Done);
                        encryptedKey = encryptedKey.Slice(0, bytesWritten);

                        var keyUnwrappers = new List<(int, KeyUnwrapper)>(1);
                        int maxKeyUnwrapSize = 0;
                        for (int i = 0; i < encryptionKeyProviders.Length; i++)
                        {
                            var keySet = encryptionKeyProviders[i].GetKeys(header);
                            for (int j = 0; j < keySet.Length; j++)
                            {
                                var key = keySet[j];
                                if (key.CanUseForKeyWrapping(alg))
                                {
                                    if (key.TryGetKeyUnwrapper(enc, algorithm, out var keyUnwrapper))
                                    {
                                        int keyUnwrapSize = keyUnwrapper.GetKeyUnwrapSize(encryptedKey.Length);
                                        keyUnwrappers.Add((keyUnwrapSize, keyUnwrapper));
                                        if (maxKeyUnwrapSize < keyUnwrapSize)
                                        {
                                            maxKeyUnwrapSize = keyUnwrapSize;
                                        }
                                    }
                                }
                            }
                        }

                        keys = new List<SymmetricJwk>(1);
                        Span<byte> unwrappedKey = maxKeyUnwrapSize <= Constants.MaxStackallocBytes ?
                            stackalloc byte[maxKeyUnwrapSize] :
                            unwrappedKeyToReturnToPool = ArrayPool<byte>.Shared.Rent(maxKeyUnwrapSize);
                        for (int i = 0; i < keyUnwrappers.Count; i++)
                        {
                            var kpv = keyUnwrappers[i];
                            var temporaryUnwrappedKey = unwrappedKey.Length != kpv.Item1 ? unwrappedKey.Slice(0, kpv.Item1) : unwrappedKey;
                            if (kpv.Item2.TryUnwrapKey(encryptedKey, temporaryUnwrappedKey, header, out int keyUnwrappedBytesWritten))
                            {
                                var jwk = SymmetricJwk.FromByteArray(unwrappedKey.Slice(0, keyUnwrappedBytesWritten).ToArray(), false);
                                keys.Add(jwk);
                            }
                        }
                    }
                    finally
                    {
                        if (encryptedKeyToReturnToPool != null)
                        {
                            ArrayPool<byte>.Shared.Return(encryptedKeyToReturnToPool, true);
                        }

                        if (unwrappedKeyToReturnToPool != null)
                        {
                            ArrayPool<byte>.Shared.Return(unwrappedKeyToReturnToPool, true);
                        }
                    }
                }
                else
                {
                    keys = null;
                    return false;
                }
            }

            return keys.Count != 0;
        }
    }
}