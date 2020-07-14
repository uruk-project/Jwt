// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System;
using System.Buffers;
using System.Diagnostics;
using System.Security.Cryptography;
using JsonWebToken.Internal;

namespace JsonWebToken
{
    /// <summary>
    /// Defines an encrypted JWT with a <typeparamref name="TPayload"/> payload.
    /// </summary>
    public abstract class EncryptedJwtDescriptor<TPayload> : JwtDescriptor<TPayload>
    {
#if NETSTANDARD2_0 || NET461 || NET47
        private static readonly RandomNumberGenerator _randomNumberGenerator = RandomNumberGenerator.Create();
#endif

        /// <summary>
        /// Initializes a new instance of <see cref="EncryptedJwtDescriptor{TPayload}"/>.
        /// </summary>
        /// <param name="header"></param>
        /// <param name="payload"></param>
        protected EncryptedJwtDescriptor(JwtObject header, TPayload payload)
            : base(header, payload)
        {
        }

        /// <summary>
        /// Initializes a new instance of <see cref="EncryptedJwtDescriptor{TPayload}"/>.
        /// </summary>
        /// <param name="payload"></param>
        protected EncryptedJwtDescriptor(TPayload payload)
            : base(payload)
        {
        }

        /// <summary>
        /// Gets or sets the algorithm header.
        /// </summary>
        public KeyManagementAlgorithm? Algorithm
        {
            get => (KeyManagementAlgorithm?)GetHeaderParameter<byte[]>(HeaderParameters.AlgUtf8);
            set => SetHeaderParameter(HeaderParameters.AlgUtf8, (byte[]?)value);
        }

        /// <summary>
        /// Gets or sets the encryption algorithm.
        /// </summary>
        public EncryptionAlgorithm? EncryptionAlgorithm
        {
            get => (EncryptionAlgorithm?)GetHeaderParameter<byte[]>(HeaderParameters.EncUtf8);
            set => SetHeaderParameter(HeaderParameters.EncUtf8, (byte[]?)value);
        }

        /// <summary>
        /// Gets or sets the compression algorithm.
        /// </summary>
        public CompressionAlgorithm? CompressionAlgorithm
        {
            get => (CompressionAlgorithm?)GetHeaderParameter<byte[]>(HeaderParameters.ZipUtf8);
            set => SetHeaderParameter(HeaderParameters.ZipUtf8, (byte[]?)value);
        }

        /// <summary>
        /// Gets the <see cref="Jwt"/> used.
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
            EncryptionAlgorithm? encryptionAlgorithm = EncryptionAlgorithm;
            var key = Key;
            if (key is null)
            {
                ThrowHelper.ThrowKeyNotFoundException();
                return;
            }

            KeyManagementAlgorithm? contentEncryptionAlgorithm = Algorithm ?? key.KeyManagementAlgorithm;
            if (key.TryGetKeyWrapper(encryptionAlgorithm, contentEncryptionAlgorithm, out var keyWrapper))
            {
                var header = Header;
                Span<byte> wrappedKey = stackalloc byte[keyWrapper.GetKeyWrapSize()];
                var cek = keyWrapper.WrapKey(null, header, wrappedKey);
                if (cek.TryGetAuthenticatedEncryptor(encryptionAlgorithm, out AuthenticatedEncryptor? encryptor))
                {
                    if (header.ContainsKey(WellKnownProperty.Kid) && key.Kid != null)
                    {
                        header.Replace(new JwtProperty(WellKnownProperty.Kid, key.Kid));
                    }

                    try
                    {
                        using var bufferWriter = new PooledByteBufferWriter();
                        header.Serialize(bufferWriter);
                        var headerJson = bufferWriter.WrittenSpan;
                        int headerJsonLength = headerJson.Length;
                        int base64EncodedHeaderLength = Base64Url.GetArraySizeRequiredToEncode(headerJsonLength);

                        byte[]? buffer64HeaderToReturnToPool = null;
                        byte[]? arrayCiphertextToReturnToPool = null;

                        Span<byte> base64EncodedHeader = base64EncodedHeaderLength > Constants.MaxStackallocBytes
                               ? (buffer64HeaderToReturnToPool = ArrayPool<byte>.Shared.Rent(base64EncodedHeaderLength)).AsSpan(0, base64EncodedHeaderLength)
                                 : stackalloc byte[base64EncodedHeaderLength];

                        try
                        {
                            TryEncodeUtf8ToBase64Url(headerJson, base64EncodedHeader, out int bytesWritten);

                            Compressor? compressor = null;
                            var compressionAlgorithm = CompressionAlgorithm;
                            if (!(compressionAlgorithm is null))
                            {
                                compressor = compressionAlgorithm.Compressor;
                                if (compressor == null)
                                {
                                    ThrowHelper.ThrowNotSupportedException_CompressionAlgorithm(compressionAlgorithm);
                                }
                                else
                                {
                                    payload = compressor.Compress(payload);
                                }
                            }

                            int ciphertextLength = encryptor.GetCiphertextSize(payload.Length);
                            Span<byte> tag = stackalloc byte[encryptor.GetTagSize()];
                            Span<byte> ciphertext = ciphertextLength > Constants.MaxStackallocBytes
                                                        ? (arrayCiphertextToReturnToPool = ArrayPool<byte>.Shared.Rent(ciphertextLength)).AsSpan(0, ciphertextLength)
                                                        : stackalloc byte[ciphertextLength];
#if NETSTANDARD2_0 || NET461 || NET47
                            var nonce = new byte[encryptor.GetNonceSize()];
                            _randomNumberGenerator.GetBytes(nonce);
#else
                            Span<byte> nonce = stackalloc byte[encryptor.GetNonceSize()];
                            RandomNumberGenerator.Fill(nonce);
#endif
                            encryptor.Encrypt(payload, nonce, base64EncodedHeader, ciphertext, tag);

                            int encryptionLength =
                                base64EncodedHeader.Length
                                + encryptor.GetBase64NonceSize()
                                + Base64Url.GetArraySizeRequiredToEncode(ciphertext.Length)
                                + encryptor.GetBase64TagSize()
                                + (Constants.JweSegmentCount - 1);
                            encryptionLength += Base64Url.GetArraySizeRequiredToEncode(wrappedKey.Length);

                            Span<byte> encryptedToken = output.GetSpan(encryptionLength);

                            base64EncodedHeader.CopyTo(encryptedToken);
                            encryptedToken[bytesWritten++] = Constants.ByteDot;
                            bytesWritten += Base64Url.Encode(wrappedKey, encryptedToken.Slice(bytesWritten));

                            encryptedToken[bytesWritten++] = Constants.ByteDot;
                            bytesWritten += Base64Url.Encode(nonce, encryptedToken.Slice(bytesWritten));
                            encryptedToken[bytesWritten++] = Constants.ByteDot;
                            bytesWritten += Base64Url.Encode(ciphertext, encryptedToken.Slice(bytesWritten));
                            encryptedToken[bytesWritten++] = Constants.ByteDot;
                            bytesWritten += Base64Url.Encode(tag, encryptedToken.Slice(bytesWritten));
                            Debug.Assert(encryptionLength == bytesWritten);
                            output.Advance(encryptionLength);
                        }
                        finally
                        {
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
                        ThrowHelper.ThrowCryptographicException_EncryptionFailed(encryptionAlgorithm, key, ex);
                    }
                }
                else
                {
                    ThrowHelper.ThrowNotSupportedException_EncryptionAlgorithm(encryptionAlgorithm);
                }
            }
            else
            {
                ThrowHelper.ThrowNotSupportedException_AlgorithmForKeyWrap(encryptionAlgorithm);
            }
        }

        private static bool TryEncodeUtf8ToBase64Url(ReadOnlySpan<byte> input, Span<byte> destination, out int bytesWritten)
        {
            bytesWritten = Base64Url.Encode(input, destination);
            return bytesWritten == destination.Length;
        }

        /// <inheritsdoc />
        protected override void OnKeyChanged(Jwk? key)
        {
            if (!(key is null) && !(key.KeyManagementAlgorithm is null))
            {
                Algorithm = key.KeyManagementAlgorithm;
            }
        }
    }
}