using Newtonsoft.Json.Linq;
using System;
using System.Buffers;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;

namespace JsonWebToken
{
    public abstract class EncryptedJwtDescriptor<TPayload> : JwtDescriptor<TPayload> where TPayload : class
    {
        private static readonly RandomNumberGenerator _randomNumberGenerator = RandomNumberGenerator.Create();

        public EncryptedJwtDescriptor(JObject header, TPayload payload)
            : base(header, payload)
        {
        }

        public EncryptedJwtDescriptor(TPayload payload)
            : base(payload)
        {
        }

        public EncryptionAlgorithm EncryptionAlgorithm
        {
            get => (EncryptionAlgorithm)GetHeaderParameter(HeaderParameters.Enc);
            set => Header[HeaderParameters.Enc] = (string)value;
        }

        public CompressionAlgorithm CompressionAlgorithm
        {
            get => (CompressionAlgorithm)GetHeaderParameter(HeaderParameters.Zip);
            set => Header[HeaderParameters.Zip] = (string)value;
        }

        protected unsafe string EncryptToken(EncodingContext context, string payload)
        {
            if (payload == null)
            {
                throw new ArgumentNullException(nameof(payload));
            }

            int payloadLength = payload.Length;
            byte[] payloadToReturnToPool = null;
            Span<byte> encodedPayload = payloadLength > Constants.MaxStackallocBytes
                             ? (payloadToReturnToPool = ArrayPool<byte>.Shared.Rent(payloadLength)).AsSpan(0, payloadLength)
                             : stackalloc byte[payloadLength];

            try
            {
#if NETCOREAPP2_1
                Encoding.UTF8.GetBytes(payload, encodedPayload);
#else
                EncodingHelper.GetUtf8Bytes(payload.AsSpan(), encodedPayload);
#endif
                return EncryptToken(context, encodedPayload);
            }
            finally
            {
                if (payloadToReturnToPool != null)
                {
                    ArrayPool<byte>.Shared.Return(payloadToReturnToPool);
                }
            }
        }

        protected unsafe string EncryptToken(EncodingContext context, Span<byte> payload)
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
            Span<byte> wrappedKey = contentEncryptionAlgorithm.ProduceEncryptedKey
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

            if (header[HeaderParameters.Kid] == null && Key.Kid != null)
            {
                header[HeaderParameters.Kid] = Key.Kid;
            }

            try
            {
                var headerJson = Serialize(header);
                int headerJsonLength = headerJson.Length;
                int base64EncodedHeaderLength = Base64Url.GetArraySizeRequiredToEncode(headerJsonLength);

                byte[] arrayByteToReturnToPool = null;
                byte[] arrayCharToReturnToPool = null;
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
#if NETCOREAPP2_1
                    Encoding.UTF8.GetBytes(headerJson, utf8HeaderBuffer);
#else
                    EncodingHelper.GetUtf8Bytes(headerJson, utf8HeaderBuffer);
#endif                  
                    int bytesWritten = Base64Url.Base64UrlEncode(utf8HeaderBuffer, base64EncodedHeader);

                    Compressor compressionProvider = null;
                    if (CompressionAlgorithm != CompressionAlgorithm.Empty)
                    {
                        compressionProvider = CompressionAlgorithm.Compressor;
                        if (compressionProvider == null)
                        {
                            Errors.ThrowNotSupportedCompressionAlgorithm(CompressionAlgorithm);
                        }
                    }

                    if (compressionProvider != null)
                    {
                        payload = compressionProvider.Compress(payload);
                    }

                    int ciphertextLength = encryptionProvider.GetCiphertextSize(payload.Length);
                    Span<byte> tag = stackalloc byte[encryptionProvider.GetTagSize()];
                    Span<byte> ciphertext = ciphertextLength > Constants.MaxStackallocBytes
                                                ? (arrayCiphertextToReturnToPool = ArrayPool<byte>.Shared.Rent(ciphertextLength)).AsSpan(0, ciphertextLength)
                                                : stackalloc byte[ciphertextLength];
#if NETCOREAPP2_1
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

                    Span<byte> encryptedToken = encryptionLength > Constants.MaxStackallocBytes
                                                ? (arrayCharToReturnToPool = ArrayPool<byte>.Shared.Rent(encryptionLength)).AsSpan(0, encryptionLength)
                                                : stackalloc byte[encryptionLength];

                    base64EncodedHeader.CopyTo(encryptedToken);
                    encryptedToken[bytesWritten++] = (byte)'.';
                    if (wrappedKey != null)
                    {
                        bytesWritten += Base64Url.Base64UrlEncode(wrappedKey, encryptedToken.Slice(bytesWritten));
                    }

                    encryptedToken[bytesWritten++] = (byte)'.';
                    bytesWritten += Base64Url.Base64UrlEncode(nonce, encryptedToken.Slice(bytesWritten));
                    encryptedToken[bytesWritten++] = (byte)'.';
                    bytesWritten += Base64Url.Base64UrlEncode(ciphertext, encryptedToken.Slice(bytesWritten));
                    encryptedToken[bytesWritten++] = (byte)'.';
                    bytesWritten += Base64Url.Base64UrlEncode(tag, encryptedToken.Slice(bytesWritten));
                    Debug.Assert(encryptedToken.Length == bytesWritten);

#if NETCOREAPP2_1
                    return Encoding.UTF8.GetString(encryptedToken);
#else
                      return EncodingHelper.GetUtf8String(encryptedToken);
#endif
                }
                finally
                {
                    if (arrayCharToReturnToPool != null)
                    {
                        ArrayPool<byte>.Shared.Return(arrayCharToReturnToPool);
                    }

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
    }
}