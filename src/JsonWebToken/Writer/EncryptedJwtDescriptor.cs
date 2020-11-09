// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System;
using System.Buffers;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text.Json;
using JsonWebToken.Internal;

namespace JsonWebToken
{
    /// <summary>
    /// Defines an encrypted JWT with a <typeparamref name="TPayload"/> payload.
    /// </summary>
    public abstract class EncryptedJwtDescriptor<TPayload> : JwtDescriptor<TPayload>
    {
        private KeyManagementAlgorithm? _alg;
        private EncryptionAlgorithm? _enc;
        private CompressionAlgorithm? _zip;
#if NETSTANDARD2_0 || NET461 || NET47
        private static readonly RandomNumberGenerator _randomNumberGenerator = RandomNumberGenerator.Create();
#endif

        /// <summary>
        /// Gets or sets the algorithm header.
        /// </summary>
        public KeyManagementAlgorithm? Alg
        {
            get
            {
                if (_alg is null
                    && Header.TryGetValue(HeaderParameters.Alg, out var value)
                    && KeyManagementAlgorithm.TryParse((string?)value.Value, out _alg))
                {
                    return _alg;
                }

                return _alg;
            }

            set
            {
                if (value is null)
                {
                    ThrowHelper.ThrowArgumentNullException(ExceptionArgument.value);
                }

                _alg = value;
                Header.Add(HeaderParameters.Alg, value.Name);
            }
        }

        /// <summary>
        /// Gets or sets the encryption algorithm.
        /// </summary>
        public EncryptionAlgorithm? Enc
        {
            get
            {
                if (_enc is null
                    && Header.TryGetValue(HeaderParameters.Enc, out var value)
                    && EncryptionAlgorithm.TryParse((string?)value.Value, out _enc))
                {
                    return _enc;
                }

                return _enc;
            }

            set
            {
                if (value is null)
                {
                    ThrowHelper.ThrowArgumentNullException(ExceptionArgument.value);
                }

                _enc = value;
                Header.Add(HeaderParameters.Enc, value.Name);
            }
        }

        /// <summary>
        /// Gets or sets the compression algorithm.
        /// </summary>
        public CompressionAlgorithm? Zip
        {
            get
            {
                if (_zip is null
                    && Header.TryGetValue(HeaderParameters.Zip, out var value)
                    && CompressionAlgorithm.TryParse((string?)value.Value, out _zip))
                {
                    return _zip;
                }

                return _zip;
            }

            set
            {
                if (value is null)
                {
                    ThrowHelper.ThrowArgumentNullException(ExceptionArgument.value);
                }

                _zip = value;
                Header.Add(HeaderParameters.Zip, value.Name);
            }
        }

        /// <summary>
        /// Gets the <see cref="Jwk"/> used.
        /// </summary>
        public Jwk EncryptionKey
        {
            get => Key;
            set => Key = value;
        }

        /// <summary>
        /// Encrypt the token.
        /// </summary>
        protected void EncryptToken(ReadOnlySpan<byte> payload, IBufferWriter<byte> output)
        {
            EncryptionAlgorithm? encryptionAlgorithm = Enc;
            var key = Key;
            if (key is null)
            {
                ThrowHelper.ThrowKeyNotFoundException();
                return;
            }

            KeyManagementAlgorithm? contentEncryptionAlgorithm = Alg ?? key.KeyManagementAlgorithm;
            if (key.TryGetKeyWrapper(encryptionAlgorithm, contentEncryptionAlgorithm, out var keyWrapper))
            {
                var header = Header;
                byte[]? wrappedKeyToReturnToPool = null;
                byte[]? buffer64HeaderToReturnToPool = null;
                byte[]? arrayCiphertextToReturnToPool = null;
                int keyWrapSize = keyWrapper.GetKeyWrapSize();
                Span<byte> wrappedKey = keyWrapSize <= Constants.MaxStackallocBytes ?
                    stackalloc byte[keyWrapSize] :
                    new Span<byte>(wrappedKeyToReturnToPool = ArrayPool<byte>.Shared.Rent(keyWrapSize), 0, keyWrapSize);
                var cek = keyWrapper.WrapKey(null, header, wrappedKey);
                if (!(key.Kid is null))
                {
                    header.Add(HeaderParameters.Kid, key.Kid);
                }

                try
                {
                    using var bufferWriter = new PooledByteBufferWriter();
                    var writer = new Utf8JsonWriter(bufferWriter, Constants.NoJsonValidation);
                    header.WriteTo(writer);
                    writer.Flush();
                    var headerJson = bufferWriter.WrittenSpan;
                    int headerJsonLength = headerJson.Length;
                    int base64EncodedHeaderLength = Base64Url.GetArraySizeRequiredToEncode(headerJsonLength);

                    Span<byte> base64EncodedHeader = base64EncodedHeaderLength > Constants.MaxStackallocBytes
                           ? (buffer64HeaderToReturnToPool = ArrayPool<byte>.Shared.Rent(base64EncodedHeaderLength)).AsSpan(0, base64EncodedHeaderLength)
                             : stackalloc byte[base64EncodedHeaderLength];

                    byte[]? compressedBuffer = null;
                    try
                    {
                        int bytesWritten = Base64Url.Encode(headerJson, base64EncodedHeader);
                        Compressor? compressor = null;
                        var compressionAlgorithm = Zip;
                        if (!(compressionAlgorithm is null))
                        {
                            compressor = compressionAlgorithm.Compressor;
                            if (compressor is null)
                            {
                                ThrowHelper.ThrowNotSupportedException_CompressionAlgorithm(compressionAlgorithm);
                            }

                            // Get a buffer a bit bigger in case of data that can't be compress 
                            // and the resulting would be slighlty bigger
                            const int overheadLeeway = 32;
                            compressedBuffer = ArrayPool<byte>.Shared.Rent(payload.Length + overheadLeeway);
                            int payloadLength = compressor.Compress(payload, compressedBuffer);
                            payload = new ReadOnlySpan<byte>(compressedBuffer, 0, payloadLength);
                        }

                        var encryptor = encryptionAlgorithm!.Encryptor;
                        int ciphertextSize = encryptor.GetCiphertextSize(payload.Length);
                        int tagSize = encryptor.GetTagSize();
                        int bufferSize = ciphertextSize + tagSize;
                        Span<byte> buffer = bufferSize > Constants.MaxStackallocBytes
                                                    ? (arrayCiphertextToReturnToPool = ArrayPool<byte>.Shared.Rent(bufferSize))
                                                    : stackalloc byte[bufferSize];
                        Span<byte> tag = buffer.Slice(ciphertextSize, tagSize);
                        Span<byte> ciphertext = buffer.Slice(0, ciphertextSize);

#if NETSTANDARD2_0 || NET461 || NET47
                        var nonce = new byte[encryptor.GetNonceSize()];
                        _randomNumberGenerator.GetBytes(nonce);
#else
                        Span<byte> nonce = stackalloc byte[encryptor.GetNonceSize()];
                        RandomNumberGenerator.Fill(nonce);
#endif
                        encryptor.Encrypt(cek.K, payload, nonce, base64EncodedHeader, ciphertext, tag, out int tagBytesWritten);

                        int encryptionLength =
                            base64EncodedHeaderLength
                            + encryptor.GetBase64NonceSize()
                            + Base64Url.GetArraySizeRequiredToEncode(ciphertextSize)
                            + Base64Url.GetArraySizeRequiredToEncode(tagBytesWritten)
                            + Base64Url.GetArraySizeRequiredToEncode(keyWrapSize)
                            + (Constants.JweSegmentCount - 1);
                        Span<byte> encryptedToken = output.GetSpan(encryptionLength);

                        base64EncodedHeader.CopyTo(encryptedToken);
                        encryptedToken[bytesWritten++] = Constants.ByteDot;
                        bytesWritten += Base64Url.Encode(wrappedKey, encryptedToken.Slice(bytesWritten));

                        encryptedToken[bytesWritten++] = Constants.ByteDot;
                        bytesWritten += Base64Url.Encode(nonce, encryptedToken.Slice(bytesWritten));

                        encryptedToken[bytesWritten++] = Constants.ByteDot;
                        bytesWritten += Base64Url.Encode(ciphertext, encryptedToken.Slice(bytesWritten));

                        encryptedToken[bytesWritten++] = Constants.ByteDot;
                        bytesWritten += Base64Url.Encode(tag.Slice(0, tagBytesWritten), encryptedToken.Slice(bytesWritten));

                        Debug.Assert(encryptionLength == bytesWritten);
                        output.Advance(encryptionLength);
                    }
                    finally
                    {
                        if (wrappedKeyToReturnToPool != null)
                        {
                            ArrayPool<byte>.Shared.Return(wrappedKeyToReturnToPool);
                        }

                        if (buffer64HeaderToReturnToPool != null)
                        {
                            ArrayPool<byte>.Shared.Return(buffer64HeaderToReturnToPool);
                        }

                        if (arrayCiphertextToReturnToPool != null)
                        {
                            ArrayPool<byte>.Shared.Return(arrayCiphertextToReturnToPool);
                        }

                        if (compressedBuffer != null)
                        {
                            ArrayPool<byte>.Shared.Return(compressedBuffer);
                        }
                    }
                }
                catch (Exception ex)
                {
                    ThrowHelper.ThrowCryptographicException_EncryptionFailed(encryptionAlgorithm, key, ex);
                }
            }
            else
            {
                ThrowHelper.ThrowNotSupportedException_AlgorithmForKeyWrap(encryptionAlgorithm);
            }
        }

        /// <inheritsdoc />
        protected override void OnKeyChanged(Jwk? key)
        {
            if (!(key is null))
            {
                var alg = key.KeyManagementAlgorithm;
                if (!(alg is null))
                {
                    Alg = alg;
                }
            }
        }
    }
}