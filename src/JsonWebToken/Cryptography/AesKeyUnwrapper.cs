// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace JsonWebToken.Internal
{
    /// <summary>
    /// Provides AES key unwrapping services.
    /// </summary>
    internal sealed class AesKeyUnwrapper : KeyUnwrapper
    {
        private const int BlockSizeInBytes = 8;

        // The default initialization vector from RFC3394
        private const ulong _defaultIV = 0XA6A6A6A6A6A6A6A6;

#if !NETSTANDARD2_0 && !NET461 && !NET47 && !NETCOREAPP2_1
        private readonly AesDecryptor _decryptor;
#else
        private readonly Aes _aes;
        private readonly ObjectPool<ICryptoTransform> _decryptorPool;
#endif
        private bool _disposed;

        public AesKeyUnwrapper(SymmetricJwk key, EncryptionAlgorithm encryptionAlgorithm, KeyManagementAlgorithm algorithm)
            : base(key, encryptionAlgorithm, algorithm)
        {
            if (algorithm.Category != AlgorithmCategory.Aes)
            {
                ThrowHelper.ThrowNotSupportedException_AlgorithmForKeyWrap(algorithm);
            }

#if !NETSTANDARD2_0 && !NET461 && !NET47 && !NETCOREAPP2_1
            if (algorithm == KeyManagementAlgorithm.Aes128KW)
            {
                _decryptor = new Aes128NiCbcDecryptor(key.K);
            }
            else if (algorithm == KeyManagementAlgorithm.Aes256KW)
            {
                _decryptor = new Aes256NiCbcDecryptor(key.K);
            }
            else if (algorithm == KeyManagementAlgorithm.Aes192KW)
            {
                _decryptor = new Aes192NiCbcDecryptor(key.K);
            }
            else
            {
                ThrowHelper.ThrowNotSupportedException_AlgorithmForKeyWrap(algorithm);
                _decryptor = new Aes128NiCbcDecryptor(default);
            }
#else
            _aes = GetSymmetricAlgorithm(key, algorithm);
            _decryptorPool = new ObjectPool<ICryptoTransform>(new PooledDecryptorPolicy(_aes));
#endif
        }

        protected override void Dispose(bool disposing)
        {
            if (!_disposed)
            {
                if (disposing)
                {
#if !NETSTANDARD2_0 && !NET461 && !NET47 && !NETCOREAPP2_1
                    _decryptor.Dispose();
#else
                    _decryptorPool.Dispose();
                    _aes.Dispose();
#endif
                }

                _disposed = true;
            }
        }

        public override bool TryUnwrapKey(ReadOnlySpan<byte> key, Span<byte> destination, JwtHeader header, out int bytesWritten)
        {
            if (key.IsEmpty)
            {
                ThrowHelper.ThrowArgumentNullException(ExceptionArgument.key);
            }

            if ((key.Length & 7) != 0)
            {
                ThrowHelper.ThrowArgumentException_KeySizeMustBeMultipleOf64(key);
            }

            if (_disposed)
            {
                ThrowHelper.ThrowObjectDisposedException(GetType());
            }

            ref byte input = ref MemoryMarshal.GetReference(key);
            ulong a = Unsafe.ReadUnaligned<ulong>(ref input);

            // The number of input blocks
            int n = key.Length - BlockSizeInBytes;

            // The set of input blocks
            Span<byte> r = stackalloc byte[n];
            ref byte rRef = ref MemoryMarshal.GetReference(r);
            Unsafe.CopyBlockUnaligned(ref rRef, ref Unsafe.AddByteOffset(ref input, (IntPtr)8), (uint)n);
            byte[] block = new byte[16];
            ref byte blockRef = ref MemoryMarshal.GetReference((Span<byte>)block);
            Span<byte> t = stackalloc byte[8];
            ref byte tRef = ref MemoryMarshal.GetReference(t);
            Unsafe.WriteUnaligned(ref tRef, 0);
            int n3 = n >> 3;
            ref byte blockEndRef = ref Unsafe.AddByteOffset(ref blockRef, (IntPtr)8);
            ref byte tRef7 = ref Unsafe.AddByteOffset(ref tRef, (IntPtr)7);
#if !NETSTANDARD2_0 && !NET461 && !NET47 && !NETCOREAPP2_1
            Span<byte> b = stackalloc byte[16];
            ref byte bRef = ref MemoryMarshal.GetReference(b);
#else
            var decryptor = _decryptorPool.Get();
            try
            {
#endif
            for (var j = 5; j >= 0; j--)
            {
                for (var i = n3; i > 0; i--)
                {
                    Unsafe.WriteUnaligned(ref tRef7, (byte)((n3 * j) + i));

                    a ^= Unsafe.ReadUnaligned<ulong>(ref tRef);
                    Unsafe.WriteUnaligned(ref blockRef, a);
                    ref byte rCurrent = ref Unsafe.AddByteOffset(ref rRef, (IntPtr)((i - 1) << 3));
                    Unsafe.WriteUnaligned(ref blockEndRef, Unsafe.ReadUnaligned<ulong>(ref rCurrent));
#if !NETSTANDARD2_0 && !NET461 && !NET47 && !NETCOREAPP2_1
                    _decryptor.DecryptBlock(ref blockRef, ref bRef);
#else
                    Span<byte> b = decryptor.TransformFinalBlock(block, 0, 16);
                    ref byte bRef = ref MemoryMarshal.GetReference(b);
#endif
                    a = Unsafe.ReadUnaligned<ulong>(ref bRef);
                    Unsafe.WriteUnaligned(ref rCurrent, Unsafe.ReadUnaligned<ulong>(ref Unsafe.AddByteOffset(ref bRef, (IntPtr)8)));
                }
            }
#if NETSTANDARD2_0 || NET461 || NET47 || NETCOREAPP2_1
            }
            finally
            {
                _decryptorPool.Return(decryptor);
            }
#endif
            if (a == _defaultIV)
            {
                ref byte destinationRef = ref MemoryMarshal.GetReference(destination);
                Unsafe.CopyBlockUnaligned(ref destinationRef, ref rRef, (uint)n);
                bytesWritten = n;
                return true;
            }

            return ThrowHelper.TryWriteError(out bytesWritten);
        }

        public override int GetKeyUnwrapSize(int wrappedKeySize)
            => GetKeyUnwrappedSize(wrappedKeySize);

        public static int GetKeyUnwrappedSize(int wrappedKeySize)
            => wrappedKeySize - BlockSizeInBytes;

#if NETSTANDARD2_0 || NET461 || NET47 || NETCOREAPP2_1
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
                aes.Mode = CipherMode.ECB; // lgtm [cs/ecb-encryption]
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

        private sealed class PooledDecryptorPolicy : PooledObjectFactory<ICryptoTransform>
        {
            private readonly Aes _aes;

            public PooledDecryptorPolicy(Aes aes)
            {
                _aes = aes;
            }

            public override ICryptoTransform Create() 
                => _aes.CreateDecryptor();
        }
#endif
    }
}
