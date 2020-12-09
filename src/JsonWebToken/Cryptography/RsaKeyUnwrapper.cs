// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System;
using System.Buffers;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace JsonWebToken.Cryptography
{
    /// <summary>
    /// Provides RSA key key unwrapping services.
    /// </summary>
    internal sealed class RsaKeyUnwrapper : KeyUnwrapper
    {
        private readonly RsaJwk _key;
        private readonly RSA _rsa;
        private readonly RSAEncryptionPadding _padding;
        private bool _disposed;

        public RsaKeyUnwrapper(RsaJwk key, EncryptionAlgorithm encryptionAlgorithm, KeyManagementAlgorithm algorithm)
            : base(encryptionAlgorithm, algorithm)
        {
            Debug.Assert(key.SupportKeyManagement(algorithm));
            Debug.Assert(algorithm.Category == AlgorithmCategory.Rsa);
            _key = key;
#if SUPPORT_SPAN_CRYPTO
            _rsa = RSA.Create(key.ExportParameters());
#else
#if NET461 || NET47
            _rsa = new RSACng();
#else
            _rsa = RSA.Create();
#endif
            _rsa.ImportParameters(key.ExportParameters());
#endif
            _padding = algorithm.Id switch
            {
                AlgorithmId.RsaOaep => RSAEncryptionPadding.OaepSHA1,
                AlgorithmId.Rsa1_5 => RSAEncryptionPadding.Pkcs1,
                AlgorithmId.RsaOaep256 => RSAEncryptionPadding.OaepSHA256,
                AlgorithmId.RsaOaep384 => RSAEncryptionPadding.OaepSHA384,
                AlgorithmId.RsaOaep512 => RSAEncryptionPadding.OaepSHA512,
                _ => throw ThrowHelper.CreateNotSupportedException_AlgorithmForKeyWrap(algorithm)
            };
        }

        /// <inheritsdoc />
        public override bool TryUnwrapKey(ReadOnlySpan<byte> key, Span<byte> destination, JwtHeaderDocument header, out int bytesWritten)
        {
            Debug.Assert(header != null);
            if (key.IsEmpty)
            {
                ThrowHelper.ThrowArgumentNullException(ExceptionArgument.key);
            }

            if (_disposed)
            {
                ThrowHelper.ThrowObjectDisposedException(GetType());
            }

#if SUPPORT_SPAN_CRYPTO
#if !NETCOREAPP
            return _rsa.TryDecrypt(key, destination, _padding, out bytesWritten);
#else

            try
            {
                // https://github.com/dotnet/corefx/pull/36601
                bool decrypted;
                if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                {
                    int keySizeBytes = _key.KeySizeInBits / 8;

                    // OpenSSL does not take a length value for the destination, so it can write out of bounds.
                    // To prevent the OOB write, decrypt into a temporary buffer.
                    if (destination.Length < keySizeBytes)
                    {
                        Span<byte> tmp = stackalloc byte[0];
                        byte[]? rent = null;

                        try
                        {
                            // RSA up through 4096 stackalloc
                            if (_key.KeySizeInBits <= 4096)
                            {
                                tmp = stackalloc byte[keySizeBytes];
                            }
                            else
                            {
                                rent = ArrayPool<byte>.Shared.Rent(keySizeBytes);
                                tmp = rent;
                            }

                            decrypted = _rsa.TryDecrypt(key, tmp, _padding, out bytesWritten);
                            if (decrypted)
                            {
                                if (bytesWritten > destination.Length)
                                {
                                    decrypted = false;
                                    bytesWritten = 0;
                                }
                                else
                                {
                                    tmp = tmp.Slice(0, bytesWritten);
                                    tmp.CopyTo(destination);
                                }

                                CryptographicOperations.ZeroMemory(tmp);
                            }
                        }
                        finally
                        {
                            if (rent != null)
                            {
                                // Already cleared
                                ArrayPool<byte>.Shared.Return(rent);
                            }
                        }
                    }
                    else
                    {
                        decrypted = _rsa.TryDecrypt(key, destination, _padding, out bytesWritten);
                    }
                }
                else
                {
                    decrypted = _rsa.TryDecrypt(key, destination, _padding, out bytesWritten);
                }

                return decrypted;
            }
            catch (CryptographicException)
            {
                bytesWritten = 0;
                return false;
            }
#endif
#else
            try
            {
                var result = _rsa.Decrypt(key.ToArray(), _padding);
                bytesWritten = result.Length;
                result.CopyTo(destination);

                return true;
            }
            catch (CryptographicException)
            {
                bytesWritten = 0;
                return false;
            }
#endif
        }

        /// <inheritsdoc />
        public override int GetKeyUnwrapSize(int wrappedKeySize)
            => EncryptionAlgorithm.RequiredKeySizeInBytes;

        /// <inheritsdoc />
        protected override void Dispose(bool disposing)
        {
            if (!_disposed)
            {
                if (disposing)
                {
                    _rsa.Dispose();
                }

                _disposed = true;
            }
        }
    }
}
