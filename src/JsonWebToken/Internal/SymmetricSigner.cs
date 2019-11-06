// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

using System;
using System.Buffers;
using System.Diagnostics;
using System.Numerics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
#if NETCOREAPP3_0
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;
#endif
using System.Security.Cryptography;

namespace JsonWebToken.Internal
{
    /// <summary>
    /// Provides signing and verifying operations using a <see cref="SymmetricJwk"/> and specifying an algorithm.
    /// </summary>
    internal sealed class SymmetricSigner : Signer
    {
        private readonly ObjectPool<KeyedHashAlgorithm> _hashAlgorithmPool;
#if NETCOREAPP3_0
        private readonly Hmac _test;
#endif
        private bool _disposed;

        /// <summary>
        /// This is the minimum <see cref="SymmetricJwk"/>.KeySize when creating and verifying signatures.
        /// </summary>
        public const int DefaultMinimumSymmetricKeySizeInBits = 128;

        private readonly int _hashSizeInBytes;
        private readonly int _base64HashSizeInBytes;
        private int _minimumKeySizeInBits = DefaultMinimumSymmetricKeySizeInBits;

        public SymmetricSigner(SymmetricJwk key, SignatureAlgorithm algorithm)
            : base(key, algorithm)
        {
            if (key.KeySizeInBits < MinimumKeySizeInBits)
            {
                ThrowHelper.ThrowArgumentOutOfRangeException_AlgorithmRequireMinimumKeySize(key, algorithm.Name, MinimumKeySizeInBits);
            }

            if (algorithm.Category != AlgorithmCategory.Hmac)
            {
                ThrowHelper.ThrowNotSupportedException_SignatureAlgorithm(algorithm);
            }

            _hashSizeInBytes = Algorithm.RequiredKeySizeInBits >> 2;
            _base64HashSizeInBytes = Base64Url.GetArraySizeRequiredToEncode(_hashSizeInBytes);
            _hashAlgorithmPool = Algorithm.Id switch
            {
                Algorithms.HmacSha256 => new ObjectPool<KeyedHashAlgorithm>(new HmacSha256ObjectPoolPolicy(key.ToArray())),
                Algorithms.HmacSha384 => new ObjectPool<KeyedHashAlgorithm>(new HmacSha384ObjectPoolPolicy(key.ToArray())),
                Algorithms.HmacSha512 => new ObjectPool<KeyedHashAlgorithm>(new HmacSha512ObjectPoolPolicy(key.ToArray())),
                _ => new ObjectPool<KeyedHashAlgorithm>(new NotSupportedObjectPoolPolicy(algorithm)),
            };
#if NETCOREAPP3_0
            _test = new Hmac(new Sha256(), key.ToArray());
#endif
        }

        /// <inheritsdoc />
        public override int HashSizeInBytes => _hashSizeInBytes;

        public override int Base64HashSizeInBytes => _base64HashSizeInBytes;

        /// <summary>
        /// Gets or sets the minimum <see cref="SymmetricJwk"/>.KeySize.
        /// </summary>
        public int MinimumKeySizeInBits
        {
            get
            {
                return _minimumKeySizeInBits;
            }

            set
            {
                if (value < DefaultMinimumSymmetricKeySizeInBits)
                {
                    ThrowHelper.ThrowArgumentOutOfRangeException_MustBeAtLeast(ExceptionArgument.value, DefaultMinimumSymmetricKeySizeInBits);
                }

                _minimumKeySizeInBits = value;
            }
        }

        /// <inheritsdoc />
        public override bool TrySign(ReadOnlySpan<byte> input, Span<byte> destination, out int bytesWritten)
        {
            if (_disposed)
            {
                ThrowHelper.ThrowObjectDisposedException(GetType());
            }

            var keyedHash = _hashAlgorithmPool.Get();
            try
            {
#if !NETSTANDARD2_0 && !NET461
                return keyedHash.TryComputeHash(input, destination, out bytesWritten);
#else
                try
                {
                    var result = keyedHash.ComputeHash(input.ToArray());
                    bytesWritten = result.Length;
                    result.CopyTo(destination);
                    return true;
                }
                catch (CryptographicException)
                {
                    return ThrowHelper.TryWriteError(out bytesWritten);
                }
#endif
            }
            finally
            {
                _hashAlgorithmPool.Return(keyedHash);
            }
        }

        /// <inheritsdoc />
        public override bool Verify(ReadOnlySpan<byte> input, ReadOnlySpan<byte> signature)
        {
            if (_disposed)
            {
                ThrowHelper.ThrowObjectDisposedException(GetType());
            }

            var keyedHash = _hashAlgorithmPool.Get();
            try
            {
#if NETSTANDARD2_0 || NET461
                Span<byte> hash = keyedHash.ComputeHash(input.ToArray());
#elif NETCOREAPP3_0
                Span<byte> hash = stackalloc byte[32];
                _test.ComputeHash(input, hash);
#else
                Span<byte> hash = stackalloc byte[_hashSizeInBytes];
                bool hashed = keyedHash.TryComputeHash(input, hash, out _);
                Debug.Assert(hashed);
#endif
                return AreEqual(signature, hash);
            }
            finally
            {
                _hashAlgorithmPool.Return(keyedHash);
            }
        }

        // Optimized byte-based AreEqual. Inspired from https://github.com/dotnet/corefx/blob/master/src/Common/src/CoreLib/System/SpanHelpers.Byte.cs
        [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
        private static bool AreEqual(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b)
        {
            int length = a.Length;
            ref byte first = ref MemoryMarshal.GetReference(a);
            ref byte second = ref MemoryMarshal.GetReference(b);
#if NETCOREAPP3_0
            if (Avx2.IsSupported && length == 32)
            {
                return Avx2.MoveMask(Avx2.CompareEqual(Unsafe.ReadUnaligned<Vector256<byte>>(ref first), Unsafe.ReadUnaligned<Vector256<byte>>(ref second))) == unchecked((int)0b1111_1111_1111_1111_1111_1111_1111_1111);
            }
            if (Sse2.IsSupported && length == 16)
            {
                return Sse2.MoveMask(Sse2.CompareEqual(Unsafe.ReadUnaligned<Vector128<byte>>(ref first), Unsafe.ReadUnaligned<Vector128<byte>>(ref second))) == 0b1111_1111_1111_1111;
            }
            else
#endif
            if (Vector.IsHardwareAccelerated && length >= Vector<byte>.Count)
            {
                Vector<byte> equals = new Vector<byte>();
                ref byte firstEnd = ref Unsafe.Add(ref first, length - Vector<byte>.Count);
                ref byte secondEnd = ref Unsafe.Add(ref second, length - Vector<byte>.Count);
                while (Unsafe.IsAddressLessThan(ref first, ref firstEnd))
                {
                    equals |= Unsafe.ReadUnaligned<Vector<byte>>(ref first) - Unsafe.ReadUnaligned<Vector<byte>>(ref second);
                    first = ref Unsafe.Add(ref first, Vector<byte>.Count);
                    second = ref Unsafe.Add(ref second, Vector<byte>.Count);
                }

                equals |= Unsafe.ReadUnaligned<Vector<byte>>(ref firstEnd) - Unsafe.ReadUnaligned<Vector<byte>>(ref secondEnd);
                return equals == Vector<byte>.Zero;
            }
            else if (length >= sizeof(long))
            {
                long equals = 0L;
                ref byte firstEnd = ref Unsafe.Add(ref first, length - sizeof(long));
                ref byte secondEnd = ref Unsafe.Add(ref second, length - sizeof(long));
                while (Unsafe.IsAddressLessThan(ref first, ref firstEnd))
                {
                    equals |= Unsafe.ReadUnaligned<long>(ref first) - Unsafe.ReadUnaligned<long>(ref second);
                    first = ref Unsafe.Add(ref first, sizeof(long));
                    second = ref Unsafe.Add(ref second, sizeof(long));
                }

                equals |= Unsafe.ReadUnaligned<long>(ref firstEnd) - Unsafe.ReadUnaligned<long>(ref secondEnd);
                return equals == 0L;
            }
            else
            {
                int equals = 0;
                ref byte firstEnd = ref Unsafe.Add(ref first, length);
                while (Unsafe.IsAddressLessThan(ref first, ref firstEnd))
                {
                    equals |= first - second;
                    first = ref Unsafe.Add(ref first, 1);
                    second = ref Unsafe.Add(ref second, 1);
                }

                return equals == 0;
            }
        }

        /// <inheritsdoc />
        protected override void Dispose(bool disposing)
        {
            if (!_disposed)
            {
                if (disposing)
                {
                    _hashAlgorithmPool.Dispose();
                }

                _disposed = true;
            }
        }

        private sealed class HmacSha256ObjectPoolPolicy : PooledObjectFactory<KeyedHashAlgorithm>
        {
            private readonly byte[] _keyBytes;

            public HmacSha256ObjectPoolPolicy(byte[] keyBytes)
            {
                _keyBytes = keyBytes;
            }

            public override KeyedHashAlgorithm Create()
            {
                return new HMACSHA256(_keyBytes);
            }
        }

        private sealed class HmacSha384ObjectPoolPolicy : PooledObjectFactory<KeyedHashAlgorithm>
        {
            private readonly byte[] _keyBytes;

            public HmacSha384ObjectPoolPolicy(byte[] keyBytes)
            {
                _keyBytes = keyBytes;
            }

            public override KeyedHashAlgorithm Create()
            {
                return new HMACSHA384(_keyBytes);
            }
        }

        private sealed class HmacSha512ObjectPoolPolicy : PooledObjectFactory<KeyedHashAlgorithm>
        {
            private readonly byte[] _keyBytes;

            public HmacSha512ObjectPoolPolicy(byte[] keyBytes)
            {
                _keyBytes = keyBytes;
            }

            public override KeyedHashAlgorithm Create()
            {
                return new HMACSHA512(_keyBytes);
            }
        }

        private sealed class NotSupportedObjectPoolPolicy : PooledObjectFactory<KeyedHashAlgorithm>
        {
            public NotSupportedObjectPoolPolicy(SignatureAlgorithm algorithm)
            {
                ThrowHelper.ThrowNotSupportedException_KeyedHashAlgorithm(algorithm);
            }

            public override KeyedHashAlgorithm Create()
            {
                throw new NotSupportedException();
            }
        }
    }
}
