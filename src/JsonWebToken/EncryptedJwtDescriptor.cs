// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

using JsonWebToken.Internal;
using Newtonsoft.Json;
using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;

namespace JsonWebToken
{
    /// <summary>
    /// Defines an encrypted JWT with a <typeparamref name="TPayload"/> payload.
    /// </summary>
    public abstract class EncryptedJwtDescriptor<TPayload> : JwtDescriptor<TPayload> where TPayload : class
    {
        private const byte dot = (byte)'.';
        private static readonly RandomNumberGenerator _randomNumberGenerator = RandomNumberGenerator.Create();

        /// <summary>
        /// Initializes a new instance of <see cref="EncryptedJwtDescriptor{TPayload}"/>.
        /// </summary>
        /// <param name="header"></param>
        /// <param name="payload"></param>
        public EncryptedJwtDescriptor(HeaderDescriptor header, TPayload payload)
            : base(header, payload)
        {
        }

        /// <summary>
        /// Initializes a new instance of <see cref="EncryptedJwtDescriptor{TPayload}"/>.
        /// </summary>
        /// <param name="payload"></param>
        public EncryptedJwtDescriptor(TPayload payload)
            : base(payload)
        {
        }

        /// <summary>
        /// Gets or sets the encryption algorithm.
        /// </summary>
        public EncryptionAlgorithm EncryptionAlgorithm
        {
            get => (EncryptionAlgorithm)GetHeaderParameter<string>(HeaderParameters.Enc);
            set => SetHeaderParameter(HeaderParameters.Enc, (string)value);
        }

        /// <summary>
        /// Gets or sets the compression algorithm.
        /// </summary>
        public CompressionAlgorithm CompressionAlgorithm
        {
            get => (CompressionAlgorithm)GetHeaderParameter<string>(HeaderParameters.Zip);
            set => SetHeaderParameter(HeaderParameters.Zip, (string)value);
        }

        /// <summary>
        /// Encrypt the token.
        /// </summary>
        protected byte[] EncryptToken(EncodingContext context, ReadOnlySpan<byte> payload)
        {
            EncryptionAlgorithm encryptionAlgorithm = EncryptionAlgorithm;
            KeyManagementAlgorithm contentEncryptionAlgorithm = (KeyManagementAlgorithm)Algorithm;
            bool isDirectEncryption = contentEncryptionAlgorithm == KeyManagementAlgorithm.Direct;

            AuthenticatedEncryptor encryptionProvider = null;
            KeyWrapper kwProvider = null;
            if (isDirectEncryption)
            {
                encryptionProvider = context.AuthenticatedEncryptionFactory.Create(Key, encryptionAlgorithm);
            }
            else
            {
                kwProvider = context.KeyWrapFactory.Create(Key, encryptionAlgorithm, contentEncryptionAlgorithm);
                if (kwProvider == null)
                {
                    Errors.ThrowNotSuportedAlgorithmForKeyWrap(encryptionAlgorithm);
                }
            }

            var header = Header;
            Span<byte> wrappedKey = contentEncryptionAlgorithm.ProduceEncryptionKey
                                        ? stackalloc byte[kwProvider.GetKeyWrapSize()]
                                        : null;
            if (!isDirectEncryption)
            {
                if (!kwProvider.TryWrapKey(null, header, wrappedKey, out var cek, out var keyWrappedBytesWritten))
                {
                    Errors.ThrowKeyWrapFailed();
                }

                encryptionProvider = cek.CreateAuthenticatedEncryptor(encryptionAlgorithm);
            }

            if (encryptionProvider == null)
            {
                Errors.ThrowNotSupportedEncryptionAlgorithm(encryptionAlgorithm);
            }

            if (header.ContainsKey(HeaderParameters.Kid) && Key.Kid != null)
            {
                header[HeaderParameters.Kid] = new JwtProperty(HeaderParameters.KidUtf8, Key.Kid);
            }

            try
            {
#if NETCOREAPP3_0
                ReadOnlySequence<byte> headerJson = default;
#else
                string headerJson = null;
#endif
                headerJson = Serialize(header, Formatting.None);
                int headerJsonLength = (int)headerJson.Length;
                int base64EncodedHeaderLength = Base64Url.GetArraySizeRequiredToEncode(headerJsonLength);

                byte[] arrayByteToReturnToPool = null;
                byte[] buffer64HeaderToReturnToPool = null;
                byte[] arrayCiphertextToReturnToPool = null;

                Span<byte> utf8HeaderBuffer = headerJsonLength > Constants.MaxStackallocBytes
                     ? (arrayByteToReturnToPool = ArrayPool<byte>.Shared.Rent(headerJsonLength)).AsSpan(0, headerJsonLength)
                     : stackalloc byte[headerJsonLength];

                Span<byte> base64EncodedHeader = base64EncodedHeaderLength > Constants.MaxStackallocBytes
                       ? (buffer64HeaderToReturnToPool = ArrayPool<byte>.Shared.Rent(base64EncodedHeaderLength)).AsSpan(0, base64EncodedHeaderLength)
                         : stackalloc byte[base64EncodedHeaderLength];

                try
                {
                    TryEncodeUtf8ToBase64Url(headerJson, base64EncodedHeader, out int bytesWritten);

                    Compressor compressor = null;
                    var compressionAlgorithm = CompressionAlgorithm;
                    if (!(compressionAlgorithm is null))
                    {
                        compressor = compressionAlgorithm.Compressor;
                        if (compressor == null)
                        {
                            Errors.ThrowNotSupportedCompressionAlgorithm(compressionAlgorithm);
                        }
                    }

                    if (compressor != null)
                    {
                        payload = compressor.Compress(payload);
                    }

                    int ciphertextLength = encryptionProvider.GetCiphertextSize(payload.Length);
                    Span<byte> tag = stackalloc byte[encryptionProvider.GetTagSize()];
                    Span<byte> ciphertext = ciphertextLength > Constants.MaxStackallocBytes
                                                ? (arrayCiphertextToReturnToPool = ArrayPool<byte>.Shared.Rent(ciphertextLength)).AsSpan(0, ciphertextLength)
                                                : stackalloc byte[ciphertextLength];
#if !NETSTANDARD2_0
                    Span<byte> nonce = stackalloc byte[encryptionProvider.GetNonceSize()];
                    RandomNumberGenerator.Fill(nonce);
#else
                    var nonce = new byte[encryptionProvider.GetNonceSize()];
                    _randomNumberGenerator.GetBytes(nonce);
#endif
                    encryptionProvider.Encrypt(payload, nonce, base64EncodedHeader, ciphertext, tag);

                    int encryptionLength =
                        base64EncodedHeader.Length
                        + Base64Url.GetArraySizeRequiredToEncode(nonce.Length)
                        + Base64Url.GetArraySizeRequiredToEncode(ciphertext.Length)
                        + Base64Url.GetArraySizeRequiredToEncode(tag.Length)
                        + (Constants.JweSegmentCount - 1);
                    if (wrappedKey != null)
                    {
                        encryptionLength += Base64Url.GetArraySizeRequiredToEncode(wrappedKey.Length);
                    }

                    var encryptedTokenToReturn = new byte[encryptionLength];
                    Span<byte> encryptedToken = encryptedTokenToReturn.AsSpan();

                    base64EncodedHeader.CopyTo(encryptedToken);
                    encryptedToken[bytesWritten++] = dot;
                    if (wrappedKey != null)
                    {
                        bytesWritten += Base64Url.Base64UrlEncode(wrappedKey, encryptedToken.Slice(bytesWritten));
                    }

                    encryptedToken[bytesWritten++] = dot;
                    bytesWritten += Base64Url.Base64UrlEncode(nonce, encryptedToken.Slice(bytesWritten));
                    encryptedToken[bytesWritten++] = dot;
                    bytesWritten += Base64Url.Base64UrlEncode(ciphertext, encryptedToken.Slice(bytesWritten));
                    encryptedToken[bytesWritten++] = dot;
                    bytesWritten += Base64Url.Base64UrlEncode(tag, encryptedToken.Slice(bytesWritten));
                    Debug.Assert(encryptedToken.Length == bytesWritten);

                    return encryptedTokenToReturn;
                }
                finally
                {
                    if (arrayByteToReturnToPool != null)
                    {
                        ArrayPool<byte>.Shared.Return(arrayByteToReturnToPool);
                    }

                    if (buffer64HeaderToReturnToPool != null)
                    {
                        ArrayPool<byte>.Shared.Return(buffer64HeaderToReturnToPool);
                    }

                    if (arrayCiphertextToReturnToPool != null)
                    {
                        ArrayPool<byte>.Shared.Return(arrayCiphertextToReturnToPool);
                    }
                }
            }
            catch (Exception ex)
            {
                Errors.ThrowEncryptionFailed(encryptionAlgorithm, Key, ex);
                return null;
            }
        }

        private static bool TryEncodeUtf8ToBase64Url(string input, Span<byte> destination, out int bytesWritten)
        {
            byte[] arrayToReturnToPool = null;
            var encodedBytes = input.Length <= Constants.MaxStackallocBytes
                  ? stackalloc byte[input.Length]
                  : (arrayToReturnToPool = ArrayPool<byte>.Shared.Rent(input.Length)).AsSpan(0, input.Length);
            try
            {
#if !NETSTANDARD2_0
                Encoding.UTF8.GetBytes(input, encodedBytes);
#else
                EncodingHelper.GetUtf8Bytes(input, encodedBytes);
#endif
                bytesWritten = Base64Url.Base64UrlEncode(encodedBytes, destination);
                return bytesWritten == destination.Length;
            }
            finally
            {
                if (arrayToReturnToPool != null)
                {
                    ArrayPool<byte>.Shared.Return(arrayToReturnToPool);
                }
            }
        }

#if NETCOREAPP3_0
        private static bool TryEncodeUtf8ToBase64Url(ReadOnlySequence<byte> input, Span<byte> destination, out int bytesWritten)
        {
            if (input.IsSingleSegment)
            {
                bytesWritten = Base64Url.Base64UrlEncode(input.First.Span, destination);
                return bytesWritten == destination.Length;
            }
            else
            {
                byte[] arrayToReturnToPool = null;
                try
                {
                    var encodedBytes = input.Length <= Constants.MaxStackallocBytes
                          ? stackalloc byte[(int)input.Length]
                          : (arrayToReturnToPool = ArrayPool<byte>.Shared.Rent((int)input.Length)).AsSpan(0, (int)input.Length);

                    input.CopyTo(encodedBytes);
                    bytesWritten = Base64Url.Base64UrlEncode(encodedBytes, destination);
                    return bytesWritten == destination.Length;
                }
                finally
                {
                    if (arrayToReturnToPool != null)
                    {
                        ArrayPool<byte>.Shared.Return(arrayToReturnToPool);
                    }
                }
            }

        }
#endif
    }
}