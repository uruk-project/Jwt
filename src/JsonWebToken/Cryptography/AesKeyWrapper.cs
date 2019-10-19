// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

using System;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace JsonWebToken.Internal
{
    /// <summary>
    /// Provides AES key wrapping services.
    /// </summary>
    internal sealed class AesKeyWrapper : KeyWrapper
    {
        private const int BlockSizeInBytes = 8;

        // The default initialization vector from RFC3394
        private const ulong _defaultIV = 0XA6A6A6A6A6A6A6A6;

#if NETCOREAPP3_0
        private readonly AesEncryptor _encryptor;
#else
        private readonly Aes _aes;
        private readonly ObjectPool<ICryptoTransform> _encryptorPool;
#endif
        private bool _disposed;

        public AesKeyWrapper(SymmetricJwk key, EncryptionAlgorithm encryptionAlgorithm, KeyManagementAlgorithm algorithm)
            : base(key, encryptionAlgorithm, algorithm)
        {
#if NETCOREAPP3_0
            if (algorithm == KeyManagementAlgorithm.Aes128KW)
            {
                _encryptor = new AesNiCbc128Encryptor(key.K);
            }
            else if (algorithm == KeyManagementAlgorithm.Aes256KW)
            {
                _encryptor = new AesNiCbc256Encryptor(key.K);
            }
            else if (algorithm == KeyManagementAlgorithm.Aes192KW)
            {
                _encryptor = new AesNiCbc192Encryptor(key.K);
            }
            else
            {
                ThrowHelper.ThrowNotSupportedException_AlgorithmForKeyWrap(algorithm);
                _encryptor = new AesNiCbc128Encryptor(default);
            }
#else
            if (algorithm.Category != AlgorithmCategory.Aes)
            {
                ThrowHelper.ThrowNotSupportedException_AlgorithmForKeyWrap(algorithm);
            }

            _aes = GetSymmetricAlgorithm(key, algorithm);
            _encryptorPool = new ObjectPool<ICryptoTransform>(new PooledEncryptorPolicy(_aes));
#endif
        }

        protected override void Dispose(bool disposing)
        {
            if (!_disposed)
            {
                if (disposing)
                {
#if NETCOREAPP3_0
                    _encryptor.Dispose();
#else
                    _encryptorPool.Dispose();
                    _aes.Dispose();
#endif
                }

                _disposed = true;
            }
        }

        /// <summary>
        /// Wrap a key using AES encryption.
        /// </summary>
        /// <param name="staticKey">the key to be wrapped. If <c>null</c>, a new <see cref="SymmetricJwk"/> will be generated.</param>
        /// <param name="header"></param>
        /// <param name="destination"></param>
        public override Jwk WrapKey(Jwk? staticKey, JwtObject header, Span<byte> destination)
        {
            if (_disposed)
            {
                ThrowHelper.ThrowObjectDisposedException(GetType());
            }

            if (destination.Length < GetKeyWrapSize())
            {
                ThrowHelper.ThrowArgumentException_DestinationTooSmall(destination.Length, GetKeyWrapSize());
            }

            var contentEncryptionKey = CreateSymmetricKey(EncryptionAlgorithm, staticKey);
            ReadOnlySpan<byte> inputBuffer = contentEncryptionKey.AsSpan();

            int n = inputBuffer.Length;
            if (destination.Length != (n + 8))
            {
                ThrowHelper.ThrowArgumentException_DestinationTooSmall(destination.Length, n + 8);
            }

            ulong a = _defaultIV;
            ref byte input = ref MemoryMarshal.GetReference(inputBuffer);
            Span<byte> r = stackalloc byte[n];
            ref byte rRef = ref MemoryMarshal.GetReference(r);
            Unsafe.CopyBlockUnaligned(ref rRef, ref input, (uint)n);
            byte[] block = new byte[16];
            ref byte blockRef = ref MemoryMarshal.GetReference((Span<byte>)block);
            ref byte block2Ref = ref Unsafe.Add(ref blockRef, 8);
            Span<byte> t = stackalloc byte[8];
            ref byte tRef = ref MemoryMarshal.GetReference(t);
            ref byte tRef7 = ref Unsafe.Add(ref tRef, 7);
            Unsafe.WriteUnaligned<ulong>(ref tRef, 0L);
            int n3 = n >> 3;
#if NETCOREAPP3_0
            Span<byte> b = stackalloc byte[16];
            ref byte bRef = ref MemoryMarshal.GetReference(b);
#else
            var encryptor = _encryptorPool.Get();
            try
            {
#endif
                for (var j = 0; j < 6; j++)
                {
                    for (var i = 0; i < n3; i++)
                    {
                        Unsafe.WriteUnaligned(ref blockRef, a);
                        Unsafe.WriteUnaligned(ref block2Ref, Unsafe.ReadUnaligned<ulong>(ref Unsafe.Add(ref rRef, i << 3)));
#if NETCOREAPP3_0
                    _encryptor.EncryptBlock(ref blockRef, ref bRef);
#else
                        Span<byte> b = encryptor.TransformFinalBlock(block, 0, 16);
                        ref byte bRef = ref MemoryMarshal.GetReference(b);
#endif
                        a = Unsafe.ReadUnaligned<ulong>(ref bRef);
                        Unsafe.WriteUnaligned(ref tRef7, (byte)((n3 * j) + i + 1));
                        a ^= Unsafe.ReadUnaligned<ulong>(ref tRef);
                        Unsafe.WriteUnaligned(ref Unsafe.Add(ref rRef, i << 3), Unsafe.ReadUnaligned<ulong>(ref Unsafe.Add(ref bRef, 8)));
                    }
                }
#if !NETCOREAPP3_0
            }
            finally
            {
                _encryptorPool.Return(encryptor);
            }
#endif
            ref byte keyBytes = ref MemoryMarshal.GetReference(destination);
            Unsafe.WriteUnaligned(ref keyBytes, a);
            Unsafe.CopyBlockUnaligned(ref Unsafe.Add(ref keyBytes, 8), ref rRef, (uint)n);

            return contentEncryptionKey;
        }

        public override int GetKeyWrapSize() 
            => GetKeyWrappedSize(EncryptionAlgorithm);

        public static int GetKeyUnwrappedSize(int wrappedKeySize) 
            => wrappedKeySize - BlockSizeInBytes;

        public static int GetKeyWrappedSize(EncryptionAlgorithm encryptionAlgorithm) 
            => encryptionAlgorithm.KeyWrappedSizeInBytes;

#if !NETCOREAPP3_0
        private static Aes GetSymmetricAlgorithm(SymmetricJwk key, KeyManagementAlgorithm algorithm)
        {
            if (algorithm.RequiredKeySizeInBits != key.KeySizeInBits)
            {
                ThrowHelper.ThrowArgumentOutOfRangeException_KeyWrapKeySizeIncorrect(algorithm, algorithm.RequiredKeySizeInBits >> 3, key, key.KeySizeInBits);
            }

            byte[] keyBytes = key.ToArray();
            Aes? aes = null;
            try
            {
                aes = Aes.Create();
                //aes.Mode = CipherMode.ECB;
                aes.Padding = PaddingMode.None;
                aes.KeySize = keyBytes.Length << 3;
                aes.Key = keyBytes;

                // Set the AES IV to Zeroes
                var iv = new byte[aes.BlockSize >> 3];
                Array.Clear(iv, 0, iv.Length);
                aes.IV = iv;

                return aes;
            }
            catch (Exception ex)
            {
                if (aes != null)
                {
                    aes.Dispose();
                }

                ThrowHelper.ThrowCryptographicException_CreateSymmetricAlgorithmFailed(key, algorithm, ex);
                throw;
            }
        }

        private sealed class PooledEncryptorPolicy : PooledObjectFactory<ICryptoTransform>
        {
            private readonly Aes _aes;

            public PooledEncryptorPolicy(Aes aes)
            {
                _aes = aes;
            }

            public override ICryptoTransform Create() 
                => _aes.CreateEncryptor();
        }
#endif
    }
}
