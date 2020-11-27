// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace JsonWebToken.Cryptography
{
    /// <summary>
    /// Provides AES key wrapping services.
    /// </summary>
    internal sealed class AesKeyWrapper : KeyWrapper
    {
        private const int BlockSizeInBytes = 8;

        // The default initialization vector from RFC3394
        private const ulong _defaultIV = 0XA6A6A6A6A6A6A6A6;

        private readonly AesBlockEncryptor _encryptor;
        private bool _disposed;

        public AesKeyWrapper(SymmetricJwk key, EncryptionAlgorithm encryptionAlgorithm, KeyManagementAlgorithm algorithm)
            : base(key, encryptionAlgorithm, algorithm)
        {
            Debug.Assert(algorithm.Category == AlgorithmCategory.Aes);
#if SUPPORT_SIMD
            if (System.Runtime.Intrinsics.X86.Aes.IsSupported && EncryptionAlgorithm.EnabledAesInstructionSet)
            {
                if (algorithm == KeyManagementAlgorithm.Aes128KW)
                {
                    _encryptor = new Aes128BlockEncryptor(key.K);
                }
                else if (algorithm == KeyManagementAlgorithm.Aes256KW)
                {
                    _encryptor = new Aes256BlockEncryptor(key.K);
                }
                else if (algorithm == KeyManagementAlgorithm.Aes192KW)
                {
                    _encryptor = new Aes192BlockEncryptor(key.K);
                }
                else
                {
                    ThrowHelper.ThrowNotSupportedException_AlgorithmForKeyWrap(algorithm);
                    _encryptor = new Aes128BlockEncryptor(default);
                }
            }
            else
            {
                _encryptor= new DefaultAesBlockEncryptor(key.K);
            }
#else
            _encryptor = new DefaultAesBlockEncryptor(key.K);
#endif
        }

        protected override void Dispose(bool disposing)
        {
            if (!_disposed)
            {
                if (disposing)
                {
                    _encryptor.Dispose();
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
        public override SymmetricJwk WrapKey(Jwk? staticKey, JwtHeader header, Span<byte> destination)
        {
            if (_disposed)
            {
                ThrowHelper.ThrowObjectDisposedException(GetType());
            }

            if (destination.Length < GetKeyWrapSize())
            {
                ThrowHelper.ThrowArgumentException_DestinationTooSmall(destination.Length, GetKeyWrapSize());
            }

            var contentEncryptionKey = CreateSymmetricKey(EncryptionAlgorithm, (SymmetricJwk?)staticKey);
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
            TryWrapKey(ref a, n, ref rRef);
            ref byte keyBytes = ref MemoryMarshal.GetReference(destination);
            Unsafe.WriteUnaligned(ref keyBytes, a);
            Unsafe.CopyBlockUnaligned(ref Unsafe.AddByteOffset(ref keyBytes, (IntPtr)8), ref rRef, (uint)n);

            return contentEncryptionKey;
        }

        private ulong TryWrapKey(ref ulong a, int n, ref byte rRef)
        {
            Span<byte> block = stackalloc byte[16];
            ref byte blockRef = ref MemoryMarshal.GetReference(block);
            ref byte block2Ref = ref Unsafe.AddByteOffset(ref blockRef, (IntPtr)8);
            Span<byte> t = stackalloc byte[8];
            ref byte tRef = ref MemoryMarshal.GetReference(t);
            ref byte tRef7 = ref Unsafe.AddByteOffset(ref tRef, (IntPtr)7);
            Unsafe.WriteUnaligned<ulong>(ref tRef, 0L);
            int n3 = n >> 3;
            Span<byte> b = stackalloc byte[16];
            ref byte bRef = ref MemoryMarshal.GetReference(b);
            for (var j = 0; j < 6; j++)
            {
                for (var i = 0; i < n3; i++)
                {
                    Unsafe.WriteUnaligned(ref blockRef, a);
                    Unsafe.WriteUnaligned(ref block2Ref, Unsafe.ReadUnaligned<ulong>(ref Unsafe.AddByteOffset(ref rRef, (IntPtr)(i << 3))));
                    _encryptor!.EncryptBlock(block, b);
                    a = Unsafe.ReadUnaligned<ulong>(ref bRef);
                    Unsafe.WriteUnaligned(ref tRef7, (byte)((n3 * j) + i + 1));
                    a ^= Unsafe.ReadUnaligned<ulong>(ref tRef);
                    Unsafe.WriteUnaligned(ref Unsafe.AddByteOffset(ref rRef, (IntPtr)(i << 3)), Unsafe.ReadUnaligned<ulong>(ref Unsafe.AddByteOffset(ref bRef, (IntPtr)8)));
                }
            }

            return a;
        }

        public override int GetKeyWrapSize()
            => GetKeyWrappedSize(EncryptionAlgorithm);

        public static int GetKeyWrappedSize(EncryptionAlgorithm encryptionAlgorithm)
            => encryptionAlgorithm.KeyWrappedSizeInBytes;
    }
}
